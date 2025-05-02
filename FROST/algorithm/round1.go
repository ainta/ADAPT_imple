package frost

import (
	"fmt"
	"sync"

	ed "filippo.io/edwards25519"
)

// round 1-1
// polynomial
func (p *Person) Make_poly() {

	for i := 0; i < t; i++ {
		bytes := Make_random_bytes(64)

		// bytes to Scalar
		s := ed.NewScalar()
		_, err := s.SetUniformBytes(bytes)
		if err != nil {
			panic(err)
		} else {
			p.Poly[i] = s
		}
	}
}

// round 1-2
// proof
func (p *Person) Compute_proof() Sigma {
	bytes := Make_random_bytes(64)

	// proof sigma = (Ri, mui)
	var R *ed.Point
	var mu *ed.Scalar

	// Ri = k * G
	// ci = H(i, phi, g^ai0, Ri)
	// mui = k + ai0 * ci over Field (GF(2^255 - 19) = Prime Number Field of curve25519)
	k, err := ed.NewScalar().SetUniformBytes(bytes)
	if err != nil {
		panic(err)
	}
	R = ed.NewGeneratorPoint().ScalarBaseMult(k)

	g_a0 := ed.NewGeneratorPoint().ScalarBaseMult(p.Poly[0])

	hash := Hashing(p.Idx, "", g_a0, R)
	c, err2 := ed.NewScalar().SetUniformBytes(hash[:])
	if err2 != nil {
		panic(err2)
	}

	mu = ed.NewScalar().MultiplyAdd(p.Poly[0], c, k)

	return Sigma{R, mu}
}

// round 1-3
// commit values
func (p *Person) Compute_commit() Commit {
	commitments := make([]*ed.Point, t)

	for i := 0; i < t; i++ {
		commitments[i] = ed.NewGeneratorPoint().ScalarBaseMult(p.Poly[i])
	}

	return Commit{commitments}
}

// round 1-5
// commit verify
func (p *Person) Verify_proof() {
	// n users' commit verify
	for idx := 0; idx < n; idx++ {
		// proof(sigma), commits
		proof := proofs[idx]
		commits := commitments[idx]

		// R, mu
		R := proof.R
		mu := proof.Mu

		// c
		hash := Hashing(idx, "", commits.C[0], R)
		c, err := ed.NewScalar().SetUniformBytes(hash[:])
		if err != nil {
			panic(err)
		}

		inv_c := ed.NewScalar().Negate(c)

		g_mu := ed.NewGeneratorPoint().ScalarBaseMult(mu)
		phi_inv_c := ed.NewGeneratorPoint().ScalarMult(inv_c, commits.C[0])

		ver := ed.NewGeneratorPoint().Add(g_mu, phi_inv_c)

		if R.Equal(ver) != 1 {
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
