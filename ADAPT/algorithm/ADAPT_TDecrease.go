package adapt

import (
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// Variables for measuring individual participant time
var tdecParticipantTimes map[int]time.Duration
var tdecTimesMutex sync.Mutex

// idx : index of p in thresholdSet
// return : si, C_i,tde, si_hat, Ri_hat, mu_i
func (p *Person) TDecrease(idx int) (*ed.Scalar, []*ed.Point, *ed.Scalar, *ed.Point, *ed.Scalar) {
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

	// compute C_i,tde = {C'_i,k} where 0 <= k < wi, C'_i,k=g^bi,k, bi,k = coefficients of Fi
	C_i_tde := make([]*ed.Point, len(Fi))

	for i := range Fi {
		C_i_tde[i] = ed.NewGeneratorPoint().ScalarBaseMult(Fi[i])
	}

	// compute mu_i = (lambda * F)^(w)(0)
	mui := ed.NewScalar()

	expand_lambda := Expand_poly(lambda)
	for i := range expand_lambda {
		expand_lambda[i].Multiply(expand_lambda[i], constant_lambda)
	}

	lambda_F := Divide_and_conquer_expansion(expand_lambda, Fi)
	// len(lambda * F) <= w : (lambd * F)^(w)(x) = 0
	if len(lambda_F) > w {
		mui.Set(lambda_F[w])
		wfactorial, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		for i := 1; i <= w; i++ {
			iScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(i, 64))
			wfactorial.Multiply(wfactorial, iScalar)
		}
		mui.Multiply(mui, wfactorial)
	}

	// compute Ri_hat = g^ri_hat, ri_hat is selected randomly
	bytes := Make_random_bytes(64)
	ri_hat, err := ed.NewScalar().SetUniformBytes(bytes)
	if err != nil {
		panic(err)
	}

	Ri_hat := ed.NewGeneratorPoint().ScalarBaseMult(ri_hat)

	// compute ci_hat = H3(C_i,tde, mu_i, Ri_hat)
	hash := TDecrease_H3(C_i_tde, mui, Ri_hat)
	ci_hat, _ := ed.NewScalar().SetUniformBytes(hash[:])

	// compute si_hat = ci_hat * sk_i^(0) + ri_hat
	si_hat := ed.NewScalar().MultiplyAdd(ci_hat, secretKeys[ui].sk[0], ri_hat)

	return si, C_i_tde, si_hat, Ri_hat, mui
}

// agg : verify receivings
// return : a_(w-1)
func (p *Person) Verify_TDecrease(si_List []*ed.Scalar, C_i_tde_Matrix [][]*ed.Point, si_hat_List []*ed.Scalar, Ri_hat_List []*ed.Point, mui_List []*ed.Scalar) *ed.Scalar {
	for i := 0; i < len(thresholdSet); i++ {
		// Yi == multiply k=0 to wi-1 C'_i,k^(i^k)
		ui := thresholdSet[i]
		iScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
		if err != nil {
			panic(err)
		}

		left := ed.NewIdentityPoint()
		right := ed.NewIdentityPoint()

		Yi := ed.NewIdentityPoint().Set(publicVerificationShares[ui].Y)
		left.Set(Yi)

		C_i_tde := C_i_tde_Matrix[i]

		exponentials := make([]*ed.Scalar, len(C_i_tde))
		exponentials[0], err = ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		if err != nil {
			panic(err)
		}
		for k := 1; k < len(C_i_tde_Matrix[i]); k++ {
			exponentials[k] = ed.NewScalar().Multiply(exponentials[k-1], iScalar)
		}

		for k := range C_i_tde_Matrix[i] {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(exponentials[k], C_i_tde[k]))
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to Yi")
		}

		// g^si == Ri * C'_i0^(c * lambda_i(0))
		left.Set(ed.NewIdentityPoint())
		right.Set(ed.NewIdentityPoint())

		si := si_List[i]

		left = ed.NewGeneratorPoint().ScalarBaseMult(si)
		Ri := ed.NewIdentityPoint().Set(Rs[i])
		right = ed.NewIdentityPoint().Set(Ri)

		constant_lambda, lambda := participants[ui].Generalized_lagrange_coefficient()
		lambda_zero := ed.NewScalar().Set(constant_lambda)
		for k := range lambda {
			lambda_zero.Multiply(lambda_zero, ed.NewScalar().Negate(lambda[k]))
		}

		right.Add(right, ed.NewIdentityPoint().ScalarMult(ed.NewScalar().Multiply(c, lambda_zero), C_i_tde[0]))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^si")
		}

		// g^si_hat == Yi^ci_hat * Ri_hat
		left.Set(ed.NewIdentityPoint())
		right.Set(ed.NewIdentityPoint())

		si_hat := si_hat_List[i]
		Ri_hat := Ri_hat_List[i]
		mui := mui_List[i]

		ci_hat_bytes := TDecrease_H3(C_i_tde, mui, Ri_hat)
		ci_hat, err := ed.NewScalar().SetUniformBytes(ci_hat_bytes[:])
		if err != nil {
			panic(err)
		}

		left = ed.NewGeneratorPoint().ScalarBaseMult(si_hat)
		right = ed.NewIdentityPoint().Set(Ri_hat)
		right.Add(right, ed.NewIdentityPoint().ScalarMult(ci_hat, Yi))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^si_hat")
		}
	}

	// g^(sum si) == pk^c * R
	left := ed.NewIdentityPoint()
	right := ed.NewIdentityPoint()

	sum := ed.NewScalar()
	for i := range si_List {
		sum.Add(sum, si_List[i])
	}

	left.Set(ed.NewGeneratorPoint().ScalarBaseMult(sum))

	right.Set(R)
	right.Add(right, ed.NewIdentityPoint().ScalarMult(c, Y))

	if left.Equal(right) == 0 {
		fmt.Println("verification fail to g^sum si")
	}

	// a_(w-1) = sum mu_i
	a_wm1 := ed.NewScalar()
	for i := range mui_List {
		a_wm1.Add(a_wm1, mui_List[i])
	}

	return a_wm1
}

// update key pair
func (p *Person) TDecrease_update_key_pair(a_wm1 *ed.Scalar) {
	ui := p.idx
	wi := weights[ui]

	new_sk_list := make([]*ed.Scalar, wi+1)
	new_pk := ed.NewIdentityPoint()

	// sk_i^(k) = sk_i^(k) - a_(w-1) * wPk * i^(w-k)
	oneScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))

	wPk := make([]*ed.Scalar, wi+1)
	wPk[0] = ed.NewScalar().Set(oneScalar)
	for i := 1; i <= wi; i++ {
		tmp, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(w-i+1, 64))
		wPk[i] = ed.NewScalar().Multiply(wPk[i-1], tmp)
	}

	exponentials := make([]*ed.Scalar, w+1)
	exponentials[0] = ed.NewScalar().Set(oneScalar)
	iScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
	for i := 1; i <= w; i++ {
		exponentials[i] = ed.NewScalar().Multiply(exponentials[i-1], iScalar)
	}

	for k := 0; k < wi; k++ {
		new_sk := ed.NewScalar().Set(secretKeys[ui].sk[k])
		substractor := ed.NewScalar().Set(a_wm1)
		substractor.Multiply(substractor, ed.NewScalar().Multiply(wPk[k], exponentials[w-k]))
		new_sk.Subtract(new_sk, substractor)

		new_sk_list[k] = ed.NewScalar().Set(new_sk)
	}

	// Yi = Yi * (g^(i^(w-1))^(-a_(w-1))
	new_pk.Set(publicVerificationShares[ui].Y)
	multiplier := ed.NewGeneratorPoint().ScalarBaseMult(exponentials[w-1])
	multiplier.ScalarMult(ed.NewScalar().Negate(a_wm1), multiplier)
	new_pk.Add(new_pk, multiplier)
}

func Adapt_TDecrease() {
	// Initialize time measurement map
	tdecParticipantTimes = make(map[int]time.Duration)

	agg := Get_exist_alpha()
	Calculate_common_part()

	siList := make([]*ed.Scalar, len(thresholdSet))
	C_i_tdeMatrix := make([][]*ed.Point, len(thresholdSet))
	si_hatList := make([]*ed.Scalar, len(thresholdSet))
	Ri_hatList := make([]*ed.Point, len(thresholdSet))
	muiList := make([]*ed.Scalar, len(thresholdSet))

	var wg sync.WaitGroup

	// Measure computation time for each participant
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]

			// Start time measurement for individual participant
			startTime := time.Now()

			si, C_i_tde, si_hat, Ri_hat, mui := participants[idx].TDecrease(i)

			// End time measurement and save
			elapsedTime := time.Since(startTime)
			tdecTimesMutex.Lock()
			tdecParticipantTimes[idx] = elapsedTime
			tdecTimesMutex.Unlock()

			siList[i] = ed.NewScalar().Set(si)
			C_i_tdeMatrix[i] = C_i_tde
			si_hatList[i] = ed.NewScalar().Set(si_hat)
			Ri_hatList[i] = ed.NewIdentityPoint().Set(Ri_hat)
			muiList[i] = ed.NewScalar().Set(mui)
		}(idx)
	}

	wg.Wait()

	// Print individual participant execution time
	fmt.Println("\n--- Individual Participant TDecrease Execution Time ---")
	for _, idx := range thresholdSet {
		participantName := "Participant"
		if idx == 0 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Alice"
		} else if idx == 1 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Bob"
		}
		fmt.Printf("%s %d (Weight: %d): %v\n", participantName, idx, weights[idx], tdecParticipantTimes[idx])
	}
	fmt.Println()

	// Measure verification phase time
	startVerify := time.Now()
	a_wm1 := participants[agg].Verify_TDecrease(siList, C_i_tdeMatrix, si_hatList, Ri_hatList, muiList)
	verifyTime := time.Since(startVerify)
	fmt.Printf("TDecrease verification phase time: %v\n\n", verifyTime)

	// Measure key update phase time
	startUpdate := time.Now()

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			idx := thresholdSet[i]
			participants[idx].TDecrease_update_key_pair(a_wm1)
		}(idx)
	}

	wg.Wait()

	updateTime := time.Since(startUpdate)
	fmt.Printf("TDecrease key update time: %v\n\n", updateTime)
}
