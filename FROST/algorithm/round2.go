package frost

import (
	"fmt"
	"sync"

	ed "filippo.io/edwards25519"
)

// polynomial f(x)
func (p *Person) Get_poly_result(x int) *ed.Scalar {
	res := ed.NewScalar()

	// int to 64 bytes
	bin := Int_to_bytes(x, 64)

	// xScalar : int x to Scalar type
	xScalar, err := ed.NewScalar().SetUniformBytes(bin)
	if err != nil {
		panic(err)
	}

	// pre-compute x^i
	exponentials := make([]*ed.Scalar, t)
	exponentials[0], err = ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}

	for i := 1; i < t; i++ {
		exponentials[i] = ed.NewScalar().Multiply(exponentials[i-1], xScalar)
	}

	for i := 0; i < t; i++ {
		// a_i of secret
		ai := ed.NewScalar().Set(p.Poly[i])

		res.MultiplyAdd(ai, exponentials[i], res)
	}

	return res
}

// round 2-1
// secret share
func (p *Person) Compute_secret_share() SecretShare {

	res := make([]*ed.Scalar, n)

	for i := 0; i < n; i++ {
		res[i] = p.Get_poly_result(i)
	}

	return SecretShare{res}
}

// round 2-2
// verify secret share
func (p *Person) Verify_secret_share() {
	// person의 index
	i := p.Idx

	// verify : from secret share f_l(i) (i : index of the user, j : index of other user)
	// g^(f_j(i)) == k=0 to w-1 multiply C_jk^(ui^k mod q)
	// just one fail to verification : verification fail

	// pre-compute i^k (k=0 to t-1)
	i_kList := make([]*ed.Scalar, t)
	bs := Int_to_bytes(i, 64)
	iScalar, err := ed.NewScalar().SetUniformBytes(bs)
	if err != nil {
		panic(err)
	}
	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}
	i_kList[0] = ed.NewScalar().Set(oneScalar)
	for k := 1; k < t; k++ {
		i_kList[k] = ed.NewScalar().Multiply(i_kList[k-1], iScalar)
	}

	for l := 0; l < n; l++ {
		sharedSecret := secretShares[l].Share[i]

		left := ed.NewGeneratorPoint().ScalarBaseMult(sharedSecret)
		right := ed.NewIdentityPoint()

		for k := 0; k < t; k++ {
			// phi_lk^(i^k mod q)
			phi := ed.NewGeneratorPoint().ScalarMult(i_kList[k], commitments[l].C[k])

			right.Add(right, phi)
		}

		if left.Equal(right) != 1 {
			fmt.Println("verifying fail in round2-2")
		}
	}
}

// round 2-3
// private signing share
func (p *Person) Compute_private_signing_share() *ed.Scalar {
	s := ed.NewScalar()
	i := p.Idx

	for l := 0; l < n; l++ {
		s.Add(s, secretShares[l].Share[i])
	}

	return s
}

// round2-4
// public verification share
// s : private signing share
func Compute_verification_share(s *ed.Scalar) PublicVerificationShare {
	y := ed.NewGeneratorPoint().ScalarBaseMult(s)
	return PublicVerificationShare{y}
}

// group public key
func Compute_group_public_key() *ed.Point {

	res := ed.NewIdentityPoint()

	for j := 0; j < n; j++ {
		res.Add(res, commitments[j].C[0])
	}

	return res
}

// verify verification share
func (p *Person) Verify_verification_share() {
	left := ed.NewIdentityPoint()
	i := p.Idx

	left.Set(publicVerificationShares[i].Y)

	right := ed.NewIdentityPoint()

	// pre-compute i^k (k=0 to t-1)
	i_kList := make([]*ed.Scalar, t)
	bs := Int_to_bytes(i, 64)
	iScalar, err := ed.NewScalar().SetUniformBytes(bs)
	if err != nil {
		panic(err)
	}
	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}
	i_kList[0] = ed.NewScalar().Set(oneScalar)
	for k := 1; k < t; k++ {
		i_kList[k] = ed.NewScalar().Multiply(i_kList[k-1], iScalar)
	}

	for j := 0; j < n; j++ {
		for k := 0; k < t; k++ {
			// phi_jk^(i^k mod q)
			phi := ed.NewGeneratorPoint().ScalarMult(i_kList[k], commitments[j].C[k])

			right.Add(right, phi)
		}
	}

	if left.Equal(right) != 1 {
		fmt.Println("verifying fail in round2-4")
	}
}

// round2
func Round2() {

	var wg sync.WaitGroup

	// 2-1
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			secretShares[i] = participants[i].Compute_secret_share()
		}(i)
	}

	wg.Wait()

	// 2-2
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			participants[i].Verify_secret_share()
		}(i)
	}

	wg.Wait()

	// 2-3 and 2-4
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			// private signing share (s_i)
			si := participants[i].Compute_private_signing_share()
			// public verification share (Y_i = g^s_i)
			publicVerificationShares[i] = Compute_verification_share(si)
		}(i)
	}

	wg.Wait()

	// group public key
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			groupPublicKey.Set(Compute_group_public_key())
		}(i)
	}

	wg.Wait()
}
