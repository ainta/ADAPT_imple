package adapt

import (
	"fmt"
	"sync"

	ed "filippo.io/edwards25519"
)

// round 1-1
// make polynomial
func (p *Person) Make_poly() {

	for i := 0; i < w; i++ {
		// select 64 bytes values (64 bytes : by using lib)
		bytes := Make_random_bytes(64)

		// bytes to Scalar
		s, err := ed.NewScalar().SetUniformBytes(bytes)
		if err != nil {
			panic(err)
		} else {
			p.poly[i] = s
		}
	}
}

// round 1-2
// proof
func (p *Person) Compute_proof() Pi {
	bytes := Make_random_bytes(64)

	// proof pi = (Ri, sigmai)
	var Ri *ed.Point
	var sigmai *ed.Scalar

	// Ri = ri * G
	// ci = H(i, str, C_i,0, Ri, Tbar_i)
	// sigma_i = ri + f_i(0) * ci over Field
	ri, err := ed.NewScalar().SetUniformBytes(bytes)
	if err != nil {
		panic(err)
	}
	Ri = ed.NewGeneratorPoint().ScalarBaseMult(ri)

	C_i0 := ed.NewGeneratorPoint().ScalarBaseMult(p.poly[0])

	hash := Hashing(p.idx, "", C_i0, Ri)
	ci, err2 := ed.NewScalar().SetUniformBytes(hash[:])
	if err2 != nil {
		panic(err2)
	}

	sigmai = ed.NewScalar().MultiplyAdd(p.poly[0], ci, ri)

	return Pi{Ri, sigmai}
}

// round 1-3
// commit
func (p *Person) Compute_commit() Commit {
	commitments := make([]*ed.Point, w)

	for i := 0; i < w; i++ {
		commitments[i] = ed.NewGeneratorPoint().ScalarBaseMult(p.poly[i])
	}

	return Commit{commitments}
}

// round 1-5
// commit verify
func (p *Person) Verify_proof() {
	for idx := 0; idx < n; idx++ {
		// received proof(Pi), commits
		proof := proofs[idx]
		commits := commitments[idx]

		// R, mu
		R := proof.R
		sigma := proof.sigmaBar

		// c
		hash := Hashing(idx, "", commits.C[0], R)
		c, err := ed.NewScalar().SetUniformBytes(hash[:])
		if err != nil {
			panic(err)
		}

		left := ed.NewGeneratorPoint().ScalarBaseMult(sigma)

		right := ed.NewIdentityPoint().Set(R)
		right.Add(right, ed.NewIdentityPoint().ScalarMult(c, commits.C[0]))

		if left.Equal(right) != 1 {
			fmt.Println("verifying fail in round1-5")
		}
	}
}

// round1
func Round1() {

	var wg sync.WaitGroup

	// 1-1
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			participants[i].Make_poly()
		}(i)
	}

	wg.Wait()

	// 1-2
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			proofs[i] = participants[i].Compute_proof()
		}(i)
	}

	wg.Wait()

	// 1-3
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			commitments[i] = participants[i].Compute_commit()
		}(i)
	}

	wg.Wait()

	// 1-4
	// pass (networking)

	// 1-5
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			participants[i].Verify_proof()
		}(i)
	}

	wg.Wait()
}
