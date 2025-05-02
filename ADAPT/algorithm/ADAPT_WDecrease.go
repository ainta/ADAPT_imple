package adapt

import (
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// Variables for measuring individual participant time
var wdecParticipantTimes map[int]time.Duration
var wdecTimesMutex sync.Mutex

// ul : user that want to decrease weight
// wl : weight of user that want to decrease weight
// idx : index of p in thresholdSet
func (p *Person) WDecrease(ul, wl, idx int) ([]*ed.Point, *ed.Scalar, []*ed.Point, [][]*ed.Scalar, []*ed.Scalar, []*ed.Point) {
	ui := p.idx

	// compute Fi
	constant_lambda, lambda := p.Generalized_lagrange_coefficient()
	skList := secretKeys[ui].sk
	Fi := p.Compute_Fi(constant_lambda, lambda, skList)

	// compute si : si = di + ei * rhoi + c * (lambda_i * Fi)(0)
	lambda_F_zero, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	lambda_F_zero.Multiply(lambda_F_zero, constant_lambda)
	for i := range lambda {
		lambda_F_zero.Multiply(lambda_F_zero, ed.NewScalar().Negate(lambda[i]))
	}
	lambda_F_zero.Multiply(lambda_F_zero, Fi[0])

	di := ed.NewScalar().Set(privateNonceLists[ui].Nonces[availableIdx].d)
	ei := ed.NewScalar().Set(privateNonceLists[ui].Nonces[availableIdx].e)
	rhoi := ed.NewScalar().Set(rhos[idx].Rho)

	si := ed.NewScalar()
	si.Add(si, di)
	si.Add(si, ed.NewScalar().Multiply(ei, rhoi))
	si.Add(si, ed.NewScalar().Multiply(c, lambda_F_zero))

	// compute C_i,wde = {C'_i,k} where 0 <= k < wi, C'_i,k=g^bi,k, bi,k = coefficients of Fi
	C_i_wde := make([]*ed.Point, len(Fi))

	for i := range Fi {
		C_i_wde[i] = ed.NewGeneratorPoint().ScalarBaseMult(Fi[i])
	}

	// pick h_i(x) = h_i,k * x^k where k=1 to w_l
	h_poly := make([]*ed.Scalar, wl+1)
	h_poly[0] = ed.NewScalar()
	for k := 1; k <= wl; k++ {
		h, _ := ed.NewScalar().SetUniformBytes(Make_random_bytes(64))
		h_poly[k] = ed.NewScalar().Set(h)
	}

	// C_i,wde_hat = {C_i,k_hat} C_i,k_hat = g^h_ik
	C_i_wde_hat := make([]*ed.Point, wl+1)
	C_i_wde_hat[0] = ed.NewIdentityPoint()
	for k := 1; k <= wl; k++ {
		C_i_wde_hat[k] = ed.NewGeneratorPoint().ScalarBaseMult(h_poly[k])
	}

	// h_i^(k)(j) : if j = l, 0 <= k < wj-1, else 0 <= k < wj
	h_der_matrix := make([][]*ed.Scalar, len(thresholdSet))
	der_coefficients := Compute_derivation_coefficients(h_poly)

	for j := 0; j < len(thresholdSet); j++ {
		uj := thresholdSet[j]
		wj := weights[uj]

		if uj == ul {
			h_der_matrix[j] = Compute_sequential_derivation(wj-2, uj, len(h_poly), der_coefficients)
		} else {
			h_der_matrix[j] = Compute_sequential_derivation(wj-1, uj, len(h_poly), der_coefficients)
		}
	}

	// r_ij_hat, R_ij_hat
	r_hat_list := make([]*ed.Scalar, len(thresholdSet))
	R_hat_list := make([]*ed.Point, len(thresholdSet))
	for j := range R_hat_list {
		r, _ := ed.NewScalar().SetUniformBytes(Make_random_bytes(64))
		r_hat_list[j] = ed.NewScalar().Set(r)
		R_hat_list[j] = ed.NewIdentityPoint().ScalarBaseMult(r_hat_list[j])
	}

	// c_ij_hat = H3(C_i,wde, {h_i^(k)(j)}, R_ij_hat)
	c_hat_list := make([]*ed.Scalar, len(thresholdSet))
	for j := range c_hat_list {
		hash := WDecrease_H3(C_i_wde, h_der_matrix[j], R_hat_list[j])
		hashScalar, err := ed.NewScalar().SetUniformBytes(hash[:])
		if err != nil {
			panic(err)
		}
		c_hat_list[j] = ed.NewScalar().Set(hashScalar)
	}

	// s_ij_hat = c_ij_hat * sk_i^(0) + r_ij_hat
	s_hat_list := make([]*ed.Scalar, len(thresholdSet))
	for j := range s_hat_list {
		s_hat := ed.NewScalar().Set(c_hat_list[j])
		s_hat.Multiply(s_hat, secretKeys[ui].sk[0])
		s_hat.Add(s_hat, r_hat_list[j])

		s_hat_list[j] = ed.NewScalar().Set(s_hat)
	}

	return C_i_wde, si, R_hat_list, h_der_matrix, s_hat_list, C_i_wde_hat
}

// ul, wl : user that want to decrease weight
// idx : index of p in thresholdSet
func (p *Person) Verify_WDecrease(ul, wl, idx int, C_j_wde_Matrix [][]*ed.Point, sj_List []*ed.Scalar, R_hat_Matrix [][]*ed.Point, h_der_Matrix [][][]*ed.Scalar, s_hat_Matrix [][]*ed.Scalar, C_j_wde_hat_Matrix [][]*ed.Point) {
	ui := p.idx

	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}

	iexponentials := make([]*ed.Scalar, wl+1)
	iScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
	if err != nil {
		panic(err)
	}

	iexponentials[0] = ed.NewScalar().Set(oneScalar)
	for k := 1; k <= wl; k++ {
		iexponentials[k] = ed.NewScalar().Multiply(iexponentials[k-1], iScalar)
	}

	for j := 0; j < len(thresholdSet); j++ {
		uj := thresholdSet[j]

		left := ed.NewIdentityPoint()
		right := ed.NewIdentityPoint()

		// Yi == multiply k=0 to wj-1 C'_jk^(j^k)
		jScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(uj, 64))
		if err != nil {
			panic(err)
		}

		Yj := ed.NewIdentityPoint().Set(publicVerificationShares[uj].Y)
		left.Set(Yj)

		C_j_wde := C_j_wde_Matrix[j]

		exponentials := make([]*ed.Scalar, len(C_j_wde))
		exponentials[0], err = ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		if err != nil {
			panic(err)
		}
		for k := 1; k < len(C_j_wde); k++ {
			exponentials[k] = ed.NewScalar().Multiply(exponentials[k-1], jScalar)
		}

		for k := 0; k < len(C_j_wde); k++ {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(exponentials[k], C_j_wde[k]))
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to Yj")
		}

		// g^sj == Rj * C'_j0^(c * lambda_j(0))
		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(sj_List[j]))

		Rj := ed.NewIdentityPoint().Set(Rs[j])

		constant_lambda, lambda := participants[uj].Generalized_lagrange_coefficient()
		lambda_zero := ed.NewScalar().Set(constant_lambda)
		for i := range lambda {
			lambda_zero.Multiply(lambda_zero, ed.NewScalar().Negate(lambda[i]))
		}

		right.Set(ed.NewIdentityPoint().Add(Rj, ed.NewIdentityPoint().ScalarMult(ed.NewScalar().Multiply(c, lambda_zero), C_j_wde_Matrix[j][0])))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^sj")
		}

		// g^h_j(i) == multiply k=1 to wl C_jk_hat^(i^k)

		if len(h_der_Matrix[j][idx]) == 0 {
			// scalar case
			continue
		}

		h_ji := ed.NewScalar().Set(h_der_Matrix[j][idx][0])
		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(h_ji))
		right.Set(ed.NewIdentityPoint())

		for k := 1; k <= wl; k++ {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(iexponentials[k], C_j_wde_hat_Matrix[j][k]))
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^h_j(i)")
		}

		// g^s_ji_hat == Y_j^c_ji_hat * R_i_hat
		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(s_hat_Matrix[j][idx]))
		right.Set(R_hat_Matrix[j][idx])

		hash := WDecrease_H3(C_j_wde_Matrix[j], h_der_Matrix[j][idx], R_hat_Matrix[j][idx])
		c_ji_hat, _ := ed.NewScalar().SetUniformBytes(hash[:])
		right.Add(right, ed.NewIdentityPoint().ScalarMult(c_ji_hat, publicVerificationShares[uj].Y))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^s_ji_hat")
		}
	}

	// g^(sum si) == pk^c * R
	left := ed.NewIdentityPoint()
	right := ed.NewIdentityPoint()

	sum_sj := ed.NewScalar()
	for j := 0; j < len(thresholdSet); j++ {
		sum_sj.Add(sum_sj, sj_List[j])
	}
	left.Set(ed.NewGeneratorPoint().ScalarBaseMult(sum_sj))

	right.Set(R)
	right.Add(right, ed.NewIdentityPoint().ScalarMult(c, groupPublicKey))

	if left.Equal(right) == 0 {
		fmt.Println("verification fail to g^(sum si)")
	}
}

// idx : index of p in thresholdSet
// ul : decrease weight user
func (p *Person) WDecrease_update_key_pair(idx, ul int, h_der_Matrix [][][]*ed.Scalar) {
	wi := weights[p.idx]
	if p.idx == ul {
		wi -= 1
	}

	new_sk_list := make([]*ed.Scalar, wi)

	for k := 0; k < wi; k++ {
		new_sk := ed.NewScalar()
		new_sk.Add(new_sk, secretKeys[p.idx].sk[k])
		for j := 0; j < len(thresholdSet); j++ {
			new_sk.Add(new_sk, h_der_Matrix[j][idx][k])
		}
		new_sk_list[k] = ed.NewScalar().Set(new_sk)
	}
}

func Adapt_WDecrease() {
	// Initialize time measurement map
	wdecParticipantTimes = make(map[int]time.Duration)

	// alpha : WDecrease user
	alpha := Get_exist_alpha()
	w_alpha := weights[alpha]
	Calculate_common_part()

	C_i_wde_Matrix := make([][]*ed.Point, len(thresholdSet))
	si_List := make([]*ed.Scalar, len(thresholdSet))
	R_hat_Matrix := make([][]*ed.Point, len(thresholdSet))
	h_der_Matrix := make([][][]*ed.Scalar, len(thresholdSet))
	for i := 0; i < len(thresholdSet); i++ {
		h_der_Matrix[i] = make([][]*ed.Scalar, len(thresholdSet))
	}
	s_hat_Matrix := make([][]*ed.Scalar, len(thresholdSet))
	C_i_wde_hat_Matrix := make([][]*ed.Point, len(thresholdSet))

	var wg sync.WaitGroup

	// adapt WDecrease - measure individual participant time
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]

			// Start time measurement for individual participant
			startTime := time.Now()

			C_i_wde, si, R_hat_list, h_der_matrix, s_hat_list, C_i_wde_hat := participants[idx].WDecrease(alpha, w_alpha, i)

			// End time measurement and save
			elapsedTime := time.Since(startTime)
			wdecTimesMutex.Lock()
			wdecParticipantTimes[idx] = elapsedTime
			wdecTimesMutex.Unlock()

			si_List[i] = ed.NewScalar().Set(si)
			C_i_wde_Matrix[i] = C_i_wde
			s_hat_Matrix[i] = s_hat_list
			R_hat_Matrix[i] = R_hat_list
			h_der_Matrix[i] = h_der_matrix
			C_i_wde_hat_Matrix[i] = C_i_wde_hat
		}(idx)
	}

	wg.Wait()

	// Print individual participant execution time
	fmt.Println("\n--- Individual Participant WDecrease Execution Time ---")
	for _, idx := range thresholdSet {
		participantName := "Participant"
		if idx == 0 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Alice"
		} else if idx == 1 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Bob"
		}
		fmt.Printf("%s %d (Weight: %d): %v\n", participantName, idx, weights[idx], wdecParticipantTimes[idx])
	}
	fmt.Println()

	// Measure WDecrease verification time
	startVerify := time.Now()

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]
			participants[idx].Verify_WDecrease(alpha, w_alpha, i, C_i_wde_Matrix, si_List, R_hat_Matrix, h_der_Matrix, s_hat_Matrix, C_i_wde_hat_Matrix)
		}(idx)
	}

	wg.Wait()

	verifyTime := time.Since(startVerify)
	fmt.Printf("WDecrease verification phase time: %v\n\n", verifyTime)

	// Measure key update time
	startUpdate := time.Now()

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]
			participants[idx].WDecrease_update_key_pair(i, alpha, h_der_Matrix)
		}(idx)
	}

	wg.Wait()

	updateTime := time.Since(startUpdate)
	fmt.Printf("WDecrease key update time: %v\n\n", updateTime)
}
