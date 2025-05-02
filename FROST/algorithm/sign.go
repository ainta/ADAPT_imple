package frost

import (
	"fmt"
	mrand "math/rand"
	"sort"
	"sync"

	ed "filippo.io/edwards25519"
)

// initilization for sign (select sign aggregator (SA), threshold set (S))
func Sign_init() {
	availableIdx = 0

	signAgg = mrand.Intn(n)

	// alpha = t (t <= alpha <= n)
	alpha = t

	// S
	thresholdSet = Random_int_array(n, alpha)

	orderedList = make([]IndexAndPublicCommit, 0)
	bindings = make([]Binding, n)
	groupCommit = ed.NewIdentityPoint()
	groupChallenge = ed.NewScalar()
	responses = make([]Response, n)
	groupSignature = Signature{ed.NewIdentityPoint(), ed.NewScalar()}
}

// select selectionCount numbers in (0 ~ maxIdx - 1) (no duplication)
func Random_int_array(maxIdx int, selectionCount int) []int {
	perm := mrand.Perm(maxIdx)
	res := perm[:selectionCount]
	sort.Ints(res)

	return res
}

// sign 1 : B (orderedList)
func Select_sign_aggregator() {
	for i := 0; i < len(thresholdSet); i++ {
		idx := thresholdSet[i]
		i_Di_Ei := IndexAndPublicCommit{
			Idx: idx,
			DE:  publicCommitLists[idx].L[availableIdx],
		}

		orderedList = append(orderedList, i_Di_Ei)
	}
}

// sign 2 : sign aggregator sends (m, B) to Pi (networking), just make message
func Make_msg() {
	msg = []byte("FROST-TEST")
}

// sign 3 : public commit B check (check sign aggregator's fetching) (networking)

// sign 4 : binding value, group commitment, challenge
// binding values
func Compute_binding() {
	for i := 0; i < len(thresholdSet); i++ {
		l := thresholdSet[i]
		rho_l := Signing_H1(l, msg, orderedList)
		rho, err := ed.NewScalar().SetUniformBytes(rho_l[:])
		if err != nil {
			panic(err)
		}

		bindings[l] = Binding{rho}
	}
}

// group commitment
func Compute_group_commitment() {
	R := ed.NewIdentityPoint()

	for i := 0; i < len(thresholdSet); i++ {
		l := thresholdSet[i]
		rho := bindings[l].Rho
		D := publicCommitLists[l].L[availableIdx].D
		E := publicCommitLists[l].L[availableIdx].E

		E_rho := ed.NewGeneratorPoint().ScalarMult(rho, E)

		R.Add(R, D)
		R.Add(R, E_rho)
	}

	groupCommit.Set(R)
}

// group challenge
func Compute_group_challenge() {
	R := ed.NewIdentityPoint().Set(groupCommit)
	Y := ed.NewIdentityPoint().Set(groupPublicKey)

	c := Signing_H2(R, Y, msg)
	cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
	if err != nil {
		panic(err)
	}

	groupChallenge.Set(cScalar)
}

// sign 5 : zi
func (p *Person) Lagrange_coefficient() *ed.Scalar {
	// idx-th lagrange coefficient
	// idx-th coefficient : multiply (0 - x_m) / (x_idx - x_m) for m in S, m != idx

	idx := p.Idx

	one := Int_to_bytes(1, 64)
	res, err := ed.NewScalar().SetUniformBytes(one)
	if err != nil {
		panic(err)
	}

	x_idx := Int_to_bytes(idx, 64)
	x_idx_Scalar, err := ed.NewScalar().SetUniformBytes(x_idx)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(thresholdSet); i++ {
		if thresholdSet[i] == idx {
			continue
		}

		x_m := Int_to_bytes(thresholdSet[i], 64)
		x_m_Scalar, err := ed.NewScalar().SetUniformBytes(x_m)
		if err != nil {
			panic(err)
		}

		// numerator (-x_m)
		numerator := ed.NewScalar().Negate(x_m_Scalar)

		// denominator (1/(x_idx - x_m))
		denominator := ed.NewScalar().Add(x_idx_Scalar, numerator)
		denominator.Invert(denominator)

		res.Multiply(res, numerator)
		res.Multiply(res, denominator)
	}

	return res
}

// response
// zi = di + (ei * rhoi) + lambdai * si * c
// return : zi, i
func (p *Person) Compute_response() (*ed.Scalar, int) {
	idx := p.Idx

	d := ed.NewScalar().Set(privateNonceLists[idx].Nonces[availableIdx].D)
	e := ed.NewScalar().Set(privateNonceLists[idx].Nonces[availableIdx].E)
	rho := ed.NewScalar().Set(bindings[idx].Rho)
	lambda := ed.NewScalar().Set(p.Lagrange_coefficient())
	s := ed.NewScalar().Set(p.Compute_private_signing_share())
	c := ed.NewScalar().Set(groupChallenge)

	z := ed.NewScalar()
	z.Add(d, ed.NewScalar().Multiply(e, rho))
	z.Add(z, ed.NewScalar().Multiply(ed.NewScalar().Multiply(lambda, s), c))

	return z, idx
}

// sign 6 : send zi to sign aggregator : pass (networking)

// sign 7 : make signature from aggregator
func (p *Person) Compute_sign(responses []Response) error {
	j := availableIdx

	// Ri values
	RiList := make([]*ed.Point, n)

	// 7-a
	R := ed.NewIdentityPoint()

	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]

		rhoi := Signing_H1(i, msg, orderedList)
		rhoi_Scalar, err := ed.NewScalar().SetUniformBytes(rhoi[:])
		if err != nil {
			panic(err)
		}

		Di := ed.NewIdentityPoint().Set(publicCommitLists[i].L[j].D)
		Ei := ed.NewIdentityPoint().Set(publicCommitLists[i].L[j].E)
		Ei.ScalarMult(rhoi_Scalar, Ei)

		Ri := ed.NewIdentityPoint().Add(Di, Ei)
		R.Add(R, Ri)

		RiList[i] = Ri
	}

	Y := ed.NewIdentityPoint().Set(groupPublicKey)
	c := Signing_H2(R, Y, msg)
	c_Scalar, err := ed.NewScalar().SetUniformBytes(c[:])
	if err != nil {
		panic(err)
	}

	// 7-b
	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]

		// verify : g^zi == Ri * Yi^(c * lambdai)
		zi := responses[i].Z
		left := ed.NewIdentityPoint().ScalarBaseMult(zi)

		Ri := RiList[i]
		Yi := publicVerificationShares[i].Y
		lambdai := participants[i].Lagrange_coefficient()
		c_lambda := ed.NewScalar().Multiply(c_Scalar, lambdai)

		right := ed.NewIdentityPoint().Add(Ri, ed.NewIdentityPoint().ScalarMult(c_lambda, Yi))

		if left.Equal(right) != 1 {
			fmt.Println("verifying fail in sign 7-b")
		}
	}

	// 7-c
	z := ed.NewScalar()
	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]
		z.Add(z, responses[i].Z)
	}

	// 7-d
	groupSignature = Signature{R, z}

	return nil
}

// sign
func Sign() {

	var wg sync.WaitGroup

	Sign_init()

	// 1
	Select_sign_aggregator()

	// 2
	Make_msg()

	// 3 : pass

	// 4
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			Compute_binding()
			Compute_group_commitment()
			Compute_group_challenge()
		}(idx)
	}

	wg.Wait()

	// 5, 6
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			zi, i := participants[i].Compute_response()
			responses[i] = Response{zi}
		}(thresholdSet[idx])
	}

	wg.Wait()

	// 7
	err := participants[signAgg].Compute_sign(responses)
	if err != nil {
		fmt.Println(err)
	}
}

// verification
func Verify() {

	var wg sync.WaitGroup

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			R := ed.NewIdentityPoint().Set(groupSignature.R)
			z := ed.NewScalar().Set(groupSignature.Z)
			Y := ed.NewIdentityPoint().Set(groupPublicKey)
			c := Signing_H2(R, Y, msg)
			c_Scalar, err := ed.NewScalar().SetUniformBytes(c[:])
			if err != nil {
				panic(err)
			}

			// verify : R'=g^z * Y^-c
			// R' == R
			g_z := ed.NewIdentityPoint().ScalarBaseMult(z)
			neg_c := ed.NewScalar().Negate(c_Scalar)
			Y_neg_c := ed.NewIdentityPoint().ScalarMult(neg_c, Y)
			R_prime := ed.NewIdentityPoint().Add(g_z, Y_neg_c)

			if R_prime.Equal(R) == 0 {
				fmt.Println("group signature verification fail")
			}
		}(idx)
	}

	wg.Wait()
}
