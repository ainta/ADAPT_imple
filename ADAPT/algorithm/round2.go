package adapt

import (
	"fmt"
	"sync"

	ed "filippo.io/edwards25519"
)

// round 2-1
// secret shares : f_i^(m)(j) : secretShares[i].Share[j][m]
// i = p.idx
func (p *Person) Compute_secret_share() SecretShare {

	res := make([][]*ed.Scalar, n)
	for i := 0; i < n; i++ {
		res[i] = make([]*ed.Scalar, maxW)
	}

	polyLen := len(p.poly)
	coefficients := Compute_derivation_coefficients(p.poly)

	for j := 0; j < n; j++ {
		wj := weights[j]

		seqDers := Compute_sequential_derivation(wj-1, j, polyLen, coefficients)
		res[j] = seqDers
	}

	return SecretShare{res}
}

// round 2-2
// verify secret share
func (p *Person) Verify_secret_share() {
	// index of the user
	i := p.idx

	// verify : g^(f_j^(m)(i)) == multiply k=m to w-1 (C_j,k)^(kPm * i^(k-m)) for 0 <= m < w_i
	// just one fail to verification : verification fail

	// pre-compute i^k (k=0 to w-1)
	i_kList := make([]*ed.Scalar, w)
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
	for k := 1; k < w; k++ {
		i_kList[k] = ed.NewScalar().Multiply(i_kList[k-1], iScalar)
	}

	// verify g^(f_j^(m)(i)) == multiply k=m to w-1 (C_j,k)^(kPm * i^(k-m)) for 0 <= m < w_i
	wi := weights[i]

	// permutation matrix
	kPmMatrix := make([][]*ed.Scalar, w)
	for k := 0; k < w; k++ {
		kPmMatrix[k] = make([]*ed.Scalar, w)
		kPmMatrix[k][0] = ed.NewScalar().Set(oneScalar)
	}

	for k := 0; k < w; k++ {
		for m := 1; m < maxW; m++ {
			if k < m {
				continue
			}
			tmp := k - m + 1
			tmpScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(tmp, 64))
			if err != nil {
				panic(err)
			}

			kPmMatrix[k][m] = ed.NewScalar().Multiply(kPmMatrix[k][m-1], tmpScalar)
		}
	}

	for j := 0; j < n; j++ {
		if i == j {
			continue
		}
		for m := 0; m < wi; m++ {
			left := ed.NewGeneratorPoint().ScalarBaseMult(secretShares[j].Share[i][m])
			right := ed.NewIdentityPoint()

			for k := m; k < w; k++ {
				C_jk := ed.NewIdentityPoint().Set(commitments[j].C[k])
				exp := ed.NewScalar().Multiply(kPmMatrix[k][m], i_kList[k-m])
				right.Add(right, ed.NewIdentityPoint().ScalarMult(exp, C_jk))
			}

			if left.Equal(right) != 1 {
				fmt.Println("verifying fail in round2-2")
			}
		}
	}
}

// round 2-3
// partial secret (sk_i^(k))
func (p *Person) Compute_partial_secret() []*ed.Scalar {
	i := p.idx
	wi := weights[i]

	skList := make([]*ed.Scalar, wi)
	for k := 0; k < wi; k++ {
		sk := ed.NewScalar()
		for j := 0; j < n; j++ {
			sk.Add(sk, secretShares[j].Share[i][k])
		}

		skList[k] = ed.NewScalar().Set(sk)
	}

	return skList
}

// round2-4
// public verification share (pk_i = Y_i)
// sk : partial secret
func Compute_verification_share(sk *ed.Scalar) PublicVerificationShare {
	y := ed.NewGeneratorPoint().ScalarBaseMult(sk)
	return PublicVerificationShare{y}
}

// group public key (Y)
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
	i := p.idx

	left.Set(publicVerificationShares[i].Y)

	right := ed.NewIdentityPoint()

	// pre-compute i^k (k=0 to t-1)
	i_kList := make([]*ed.Scalar, w)
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
	for k := 1; k < w; k++ {
		i_kList[k] = ed.NewScalar().Multiply(i_kList[k-1], iScalar)
	}

	for j := 0; j < n; j++ {
		for k := 0; k < w; k++ {
			C := ed.NewGeneratorPoint().ScalarMult(i_kList[k], commitments[j].C[k])

			right.Add(right, C)
		}
	}

	if left.Equal(right) == 0 {
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
			// partial secret
			ski := participants[i].Compute_partial_secret()
			// sk_i store
			secretKeys[i] = SecretKey{ski}
			// public verification share (Y_i = g^sk_i^(0))
			publicVerificationShares[i] = Compute_verification_share(ski[0])
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
