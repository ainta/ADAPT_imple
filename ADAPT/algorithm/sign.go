package adapt

import (
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// Variables for measuring individual participant time
var signParticipantTimes map[int]time.Duration
var signTimesMutex sync.Mutex

// initialization for sign (global values, select aggregator, select P)
func Sign_init() {
	// available index = 0
	availableIdx = 0

	signAgg = Select_someone(n)

	bindingFactors = make([]IndexAndPublicCommit, 0)
	bindings = make([]Binding, n)
	groupCommit = ed.NewIdentityPoint()
	groupChallenge = ed.NewScalar()
	partialSignatures = make([]PartialSignature, n)
	signatureCommits = make([]SignatureCommit, n)
	groupSignature = Signature{ed.NewIdentityPoint(), ed.NewScalar()}

	// Initialize time measurement map
	signParticipantTimes = make(map[int]time.Duration)
}

// pSign 1 : B (binding factor)
func Compute_binding_factors() {
	for i := 0; i < len(thresholdSet); i++ {
		idx := thresholdSet[i]
		i_Di_Ei := IndexAndPublicCommit{
			Idx: idx,
			DE:  publicCommitLists[idx].L[availableIdx],
		}

		bindingFactors = append(bindingFactors, i_Di_Ei)
	}
}

// pSign 2 : binding (rho), group commitment (R), challenge (c)
// msg : fixed
func Make_msg() {
	msg = []byte("ADAPT-TEST")
}

// binding value (rho)
func Compute_binding() {
	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]
		rho_i := Signing_H1(msg, i, bindingFactors)
		rho, err := ed.NewScalar().SetUniformBytes(rho_i[:])
		if err != nil {
			panic(err)
		}

		bindings[i] = Binding{rho}
	}
}

// group commitment (R)
func Compute_group_commitment() {
	R := ed.NewIdentityPoint()

	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]
		rho := bindings[i].Rho
		D := publicCommitLists[i].L[availableIdx].D
		E := publicCommitLists[i].L[availableIdx].E

		E_rho := ed.NewGeneratorPoint().ScalarMult(rho, E)

		R.Add(R, D)
		R.Add(R, E_rho)
	}

	groupCommit.Set(R)
}

// group challenge (c)
func Compute_group_challenge() {
	R := ed.NewIdentityPoint().Set(groupCommit)
	Y := ed.NewIdentityPoint().Set(groupPublicKey)

	c := Signing_H2(R, msg, Y)
	cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
	if err != nil {
		panic(err)
	}

	groupChallenge.Set(cScalar)
}

// pSign 3,4 : compute F_i using GLI
// lambda_i : i-th lagrange coefficient =  multiply ((x - x_m) / (x_i - x_m))^w_m for m in P, m != i
// (lambda_i * F_i)^(m)(x) = if x=i, sk_i^(m), else, 0
// caculation F_i : Gaussian Elimination

// generalized lagrange coefficient
// return : const, slice of coefficients
// ex) (4, [1,2,3]) : 4 * (x-1)(x-2)(x-3)
func (p *Person) Generalized_lagrange_coefficient() (*ed.Scalar, []*ed.Scalar) {
	// i-th lagrange coefficient
	// i-th coefficient : multiply ((x - x_m) / (x_i - x_m))^w_m for m in P, m != i

	idx := p.idx
	coefficients := []*ed.Scalar{}

	// calculate constant
	xiBytes := Int_to_bytes(idx, 64)
	xiScalar, err := ed.NewScalar().SetUniformBytes(xiBytes)
	if err != nil {
		panic(err)
	}

	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}

	constant := ed.NewScalar().Set(oneScalar)

	for i := 0; i < len(thresholdSet); i++ {
		if idx == thresholdSet[i] {
			continue
		}

		xmBytes := Int_to_bytes(thresholdSet[i], 64)
		xmScalar, err := ed.NewScalar().SetUniformBytes(xmBytes)
		if err != nil {
			panic(err)
		}

		tmp := ed.NewScalar().Invert(ed.NewScalar().Subtract(xiScalar, xmScalar))
		wm := weights[thresholdSet[i]]

		constant = ed.NewScalar().Multiply(constant, Fast_exponentiation(wm, tmp))

		for j := 0; j < wm; j++ {
			coefficients = append(coefficients, xmScalar)
		}
	}

	return constant, coefficients
}

// polynomial from derivations (part of GLI)
// F(x) = a_0 + a_1 x + ... + a_n x^n using F^(k)(x) (0 <= k <= n)
// a_(n-j) = ( F^(n-j)(x) - sum i=0 to j-1 (a_(n-i) * x^(j-i) * (n-i)! / (j-i)!) ) / (n-j)!
func (p *Person) Compute_polynomial_from_derivation() []*ed.Scalar {
	ui := p.idx
	wi := weights[p.idx]
	res := make([]*ed.Scalar, wi)

	// sk_i^(0), ..., sk_i^(wi-1)
	derivations := make([]*ed.Scalar, wi)
	for i := 0; i < wi; i++ {
		derivations[i] = ed.NewScalar().Set(secretKeys[ui].sk[i])
	}

	// pre-compute 0! ~ (wi-1)!
	factorials := make([]*ed.Scalar, wi)
	one, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}
	factorials[0] = ed.NewScalar().Set(one)
	for i := 1; i < wi; i++ {
		iScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(i, 64))
		if err != nil {
			panic(err)
		}
		factorials[i] = ed.NewScalar().Multiply(factorials[i-1], iScalar)
	}

	// pre-compute ui^0 ~ ui^(wi-1)
	powers := make([]*ed.Scalar, wi)
	powers[0] = ed.NewScalar().Set(one)
	uiScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
	if err != nil {
		panic(err)
	}
	for i := 1; i < wi; i++ {
		powers[i] = ed.NewScalar().Multiply(powers[i-1], uiScalar)
	}

	// a_(n-k)
	// n = wi-1
	deg := wi - 1
	res[deg] = ed.NewScalar().Multiply(derivations[deg], ed.NewScalar().Invert(factorials[deg]))
	for j := 1; j <= deg; j++ {
		der := derivations[deg-j]
		sum := ed.NewScalar()
		for i := 0; i < j; i++ {
			tmp := ed.NewScalar().Set(res[deg-i])
			tmp.Multiply(tmp, factorials[deg-i])
			tmp.Multiply(tmp, ed.NewScalar().Invert(factorials[j-i]))
			tmp.Multiply(tmp, powers[j-i])

			sum.Add(sum, tmp)
		}
		sum.Negate(sum)

		// numerator
		numerator := ed.NewScalar().Add(der, sum)
		// denominator
		denominator := ed.NewScalar().Set(factorials[deg-j])
		inv_denominator := ed.NewScalar().Invert(denominator)

		res[deg-j] = ed.NewScalar().Multiply(numerator, inv_denominator)
	}

	return res
}

// partial signature
// sigma_i = d_i + e_i * rho_i + (lambda_i * F_i)(0) * c
func (p *Person) Compute_partial_signature(lambda_F_zero *ed.Scalar) *ed.Scalar {
	idx := p.idx

	d := ed.NewScalar().Set(privateNonceLists[idx].Nonces[availableIdx].d)
	e := ed.NewScalar().Set(privateNonceLists[idx].Nonces[availableIdx].e)
	rho := ed.NewScalar().Set(bindings[idx].Rho)
	c := ed.NewScalar().Set(groupChallenge)

	sigma := ed.NewScalar().MultiplyAdd(e, rho, d)
	sigma.Add(sigma, ed.NewScalar().Multiply(lambda_F_zero, c))

	return sigma
}

// compute F_i with Gaussian Elimination
func (p *Person) Compute_Fi(constant_lambda *ed.Scalar, lambda []*ed.Scalar, constant_sk []*ed.Scalar) []*ed.Scalar {
	// lambda : (x-a0)(x-a1)...(x-ak)
	// constant_lambda : constant of lambda_i by calculating Generalized_lagrange_coefficient
	// constant_sk : sk_i^(k) that constant part of Gaussian Elimination
	// return : F_i : [b0, b1, ..., bk] = b0 + b1 x + b2 x^2 + ... + bk x^k

	idx := p.idx
	wi := weights[idx]

	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}
	iScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(idx, 64))
	if err != nil {
		panic(err)
	}

	// idx^0 ~ idx^(wi-1)
	exponentials := make([]*ed.Scalar, wi)
	exponentials[0] = ed.NewScalar().Set(oneScalar)
	for i := 1; i < wi; i++ {
		exponentials[i] = ed.NewScalar().Multiply(exponentials[i-1], iScalar)
	}

	// expansion of lambda
	lambda_poly := Expand_poly(lambda)
	for i := range lambda_poly {
		lambda_poly[i].Multiply(lambda_poly[i], constant_lambda)
	}

	polyLen := len(lambda_poly)
	lambda_der_coefficients := Compute_derivation_coefficients(lambda_poly)

	// lambda^(0)(idx) to lambda^(wi-1)(idx)
	lambda_ders := Compute_sequential_derivation(wi-1, idx, polyLen, lambda_der_coefficients)

	// base_poly : [1,1,...,1]
	base_poly := make([]*ed.Scalar, wi)
	for i := range base_poly {
		base_poly[i] = ed.NewScalar().Set(oneScalar)
	}
	// der_coefficients : F^(0)(x) to F^(wi-1)(x) coefficients
	der_coefficients := Compute_derivation_coefficients(base_poly)

	// (lambda * F)^(m)(idx) = sk_idx^(m)
	// Gaussian Elimination :
	// lambda(idx) * F(idx) = sk_idx^(0)
	// lambda^(1)(idx) * F(idx) + lambda(idx) * F^(1)(idx) = sk_idx^(1)
	// ....

	// matrix : (lambda * F) derivations coefficients to vectors
	matrix := make([][]*ed.Scalar, wi)
	for i := range matrix {
		matrix[i] = make([]*ed.Scalar, wi)
	}

	for i := 0; i < wi; i++ {
		matrix[0][i] = ed.NewScalar().Multiply(lambda_ders[0], exponentials[i])
	}

	// (lambda * F)^(k) = sum r=0 to k kCr lambda^(k-r) * F^(r)
	combinations := combination_table(wi)

	for i := 1; i < wi; i++ {
		sum := make([]*ed.Scalar, wi)
		for j := 0; j < wi; j++ {
			sum[j] = ed.NewScalar()
		}

		for j := 0; j <= i; j++ {
			binom_factor := combinations[i][j]
			lambda_der := lambda_ders[i-j]
			F_der := der_coefficients[j]
			idx_factor := make([]*ed.Scalar, wi)
			for k := 0; k < j; k++ {
				idx_factor[k] = ed.NewScalar()
			}
			idx_factor[j] = ed.NewScalar().Set(oneScalar)
			for k := j + 1; k < wi; k++ {
				idx_factor[k] = ed.NewScalar().Multiply(idx_factor[k-1], iScalar)
			}

			tmp := make([]*ed.Scalar, wi)
			for k := 0; k < wi; k++ {
				tmp[k] = ed.NewScalar().Multiply(F_der[k], idx_factor[k])
				tmp[k].Multiply(tmp[k], lambda_der)
				binom_factor_scalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(binom_factor, 64))
				tmp[k].Multiply(tmp[k], binom_factor_scalar)
			}

			for k := 0; k < wi; k++ {
				sum[k].Add(sum[k], tmp[k])
			}
		}

		for j := 0; j < wi; j++ {
			matrix[i][j] = ed.NewScalar().Set(sum[j])
		}
	}

	// Fi : calculation by gaussian elimination
	res := Gaussian_elimination(matrix, constant_sk)

	return res
}

// signature commtiment (C_i,sig)
// poly : F_i(x)
func (p *Person) Compute_signature_commitment(poly []*ed.Scalar) []*ed.Point {
	wi := weights[p.idx]
	res := make([]*ed.Point, wi)

	for k := 0; k < wi; k++ {
		res[k] = ed.NewGeneratorPoint().ScalarBaseMult(poly[k])
	}

	return res
}

// pSign 6 : pass (send (sigma_i, C_sig) to aggregator) (networking)

// pVrf 1
// Yi == multiply k=0 to wi-1 ( C'_(i,k)^(u_i^k) )
func (p *Person) Verify_public_verification_share() {
	for idx := 0; idx < len(thresholdSet); idx++ {
		ui := thresholdSet[idx]
		wi := weights[ui]

		left := ed.NewIdentityPoint()
		left.Set(publicVerificationShares[ui].Y)

		// pre-compute ui^k
		powers := make([]*ed.Scalar, wi)
		one, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		if err != nil {
			panic(err)
		}
		powers[0] = ed.NewScalar().Set(one)
		uiScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
		if err != nil {
			panic(err)
		}
		for k := 1; k < wi; k++ {
			powers[k] = ed.NewScalar().Multiply(powers[k-1], uiScalar)
		}

		right := ed.NewIdentityPoint().Set(signatureCommits[ui].C[0])
		for k := 1; k < wi; k++ {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(powers[k], signatureCommits[ui].C[k]))
		}

		if left.Equal(right) != 1 {
			fmt.Println("verification fail in pVrf : verify Yi fail")
		}
	}
}

// pVrf 2,3,4 (only exec by aggregator)
// rho_i = H1(m, ui, B), Ri = Di * Ei^rhoi for i in P
// R = multiply i in P (Ri), c = H2(R, m, Y)
// g^sigma_i == Ri * C'_(i,0)^(c*lambda_i)
func (p *Person) Verify_partial_signature() {
	j := availableIdx

	R := ed.NewIdentityPoint()
	RiList := make([]*ed.Point, n)

	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]

		rho := Signing_H1(msg, i, bindingFactors)
		rhoi, err := ed.NewScalar().SetUniformBytes(rho[:])
		if err != nil {
			panic(err)
		}
		Di := ed.NewIdentityPoint().Set(publicCommitLists[i].L[j].D)
		Ei := ed.NewIdentityPoint().Set(publicCommitLists[i].L[j].E)
		Ri := ed.NewIdentityPoint().Add(Di, ed.NewIdentityPoint().ScalarMult(rhoi, Ei))

		R.Add(R, Ri)
		RiList[i] = ed.NewIdentityPoint().Set(Ri)
	}

	c := Signing_H2(R, msg, groupPublicKey)

	// verify partial signature
	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]
		sigmai := partialSignatures[i].sigma
		Ri := ed.NewIdentityPoint().Set(RiList[i])
		Cprime := ed.NewIdentityPoint().Set(signatureCommits[i].C[0])
		cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
		if err != nil {
			panic(err)
		}

		constant, lambda := participants[i].Generalized_lagrange_coefficient()
		lambda_zero := ed.NewScalar().Set(constant)
		for j := range lambda {
			lambda_zero = ed.NewScalar().Multiply(lambda_zero, ed.NewScalar().Negate(lambda[j]))
		}

		c_lambda := ed.NewScalar().Multiply(cScalar, lambda_zero)

		left := ed.NewIdentityPoint().ScalarBaseMult(sigmai)
		right := ed.NewIdentityPoint().Add(Ri, ed.NewIdentityPoint().ScalarMult(c_lambda, Cprime))

		if left.Equal(right) != 1 {
			fmt.Println("verification fail in pVrf : verify g^sigma_i")
		}
	}

	// R of group signature
	groupSignature.R = ed.NewIdentityPoint().Set(R)
}

// Agg : compute signature
func (p *Person) Compute_aggregated_sign() {

	sigmaPrime := ed.NewScalar()
	for idx := 0; idx < len(thresholdSet); idx++ {
		i := thresholdSet[idx]
		sigmai := ed.NewScalar().Set(partialSignatures[i].sigma)
		sigmaPrime.Add(sigmaPrime, sigmai)
	}

	// R : computing when pVrf

	groupSignature.sigmaPrime = ed.NewScalar().Set(sigmaPrime)
}

// sign
func Sign() {
	Sign_init()

	// pSign
	// 1
	Compute_binding_factors()

	Make_msg()

	var wg sync.WaitGroup

	// 2, 3, 4, 5
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			// Get actual participant index
			participantIdx := thresholdSet[i]

			// Start time measurement for individual participant
			startTime := time.Now()

			Compute_binding()
			Compute_group_commitment()
			Compute_group_challenge()

			constant_lambda, lambda := participants[i].Generalized_lagrange_coefficient()
			skList := secretKeys[i].sk
			Fi := participants[i].Compute_Fi(constant_lambda, lambda, skList)

			lambda_F_zero, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
			lambda_F_zero.Multiply(lambda_F_zero, constant_lambda)
			for i := range lambda {
				lambda_F_zero.Multiply(lambda_F_zero, ed.NewScalar().Negate(lambda[i]))
			}
			lambda_F_zero.Multiply(lambda_F_zero, Fi[0])

			sigmai := participants[i].Compute_partial_signature(lambda_F_zero)
			partialSignatures[i] = PartialSignature{sigmai}

			C_isig := participants[i].Compute_signature_commitment(Fi)
			signatureCommits[i] = SignatureCommit{C_isig}

			// End time measurement and save
			elapsedTime := time.Since(startTime)
			signTimesMutex.Lock()
			signParticipantTimes[participantIdx] = elapsedTime
			signTimesMutex.Unlock()
		}(idx)
	}

	wg.Wait()

	// Print individual participant execution time
	fmt.Println("\n--- Individual Participant Signature Generation Time ---")
	for _, idx := range thresholdSet {
		participantName := "Participant"
		if idx == 0 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Alice"
		} else if idx == 1 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Bob"
		}
		fmt.Printf("%s %d (Weight: %d): %v\n", participantName, idx, weights[idx], signParticipantTimes[idx])
	}
	fmt.Println()

	// 6 : (send - networking)

	// Measure pVrf time
	verifyStartTime := time.Now()

	// 1
	participants[signAgg].Verify_public_verification_share()

	// 2,3,4
	participants[signAgg].Verify_partial_signature()

	// Agg
	participants[signAgg].Compute_aggregated_sign()

	verifyTime := time.Since(verifyStartTime)
	fmt.Printf("Signature verification and aggregation time: %v\n\n", verifyTime)
}

// Vrf
func Verify() {

	var wg sync.WaitGroup

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			left := ed.NewGeneratorPoint().ScalarBaseMult(groupSignature.sigmaPrime)
			right := ed.NewIdentityPoint().Set(groupSignature.R)

			c := Signing_H2(groupSignature.R, msg, groupPublicKey)
			cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
			if err != nil {
				panic(err)
			}

			right.Add(right, ed.NewIdentityPoint().ScalarMult(cScalar, groupPublicKey))

			if left.Equal(right) == 0 {
				fmt.Println("group signature verification fail")
			}
		}(idx)
	}

	wg.Wait()
}
