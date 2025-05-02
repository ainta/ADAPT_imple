package adapt

import (
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// Variables for measuring individual participant time
var tincParticipantTimes map[int]time.Duration
var tincTimesMutex sync.Mutex

// idx : index of p in thresholdSet
// return : si, C_i,tin (list), sij_hat (list), Ri_hat, (lambda * F)(j)*j+di+ei*rhoi (list)
func (p *Person) TIncrease(idx int) (*ed.Scalar, []*ed.Point, []*ed.Scalar, *ed.Point, []*ed.Scalar) {
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

	// compute C_i,tin = {C'_i,k} where 0 <= k < wi, C'_i,k=g^bi,k, bi,k = coefficients of Fi
	C_i_tin := make([]*ed.Point, len(Fi))

	for i := range Fi {
		C_i_tin[i] = ed.NewGeneratorPoint().ScalarBaseMult(Fi[i])
	}

	// compute Ri_hat = g^ri_hat, ri_hat is selected randomly
	bytes := Make_random_bytes(64)
	ri_hat, err := ed.NewScalar().SetUniformBytes(bytes)
	if err != nil {
		panic(err)
	}

	Ri_hat := ed.NewGeneratorPoint().ScalarBaseMult(ri_hat)

	// compute sij_hat = cij_hat * sk_i^(0) + ri_hat
	// cij_hat = H3(C_i,tin, (lambda_i * F_i)(j)*j + di + ei*rhoi, Ri_hat)
	sij_hat_list := make([]*ed.Scalar, len(thresholdSet))

	// matrix of (lambda_i * F_i)(j)*j + di + ei*rhoi (for return)
	lambda_F_etc_list := make([]*ed.Scalar, len(thresholdSet))

	oneScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}

	for j := 0; j < len(thresholdSet); j++ {
		uj := thresholdSet[j]
		jScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(uj, 64))
		if err != nil {
			panic(err)
		}

		// lambda_F_etc = (lambda_i * F_i)(j)*j + di + ei*rhoi
		lambda_F_etc := ed.NewScalar().Set(oneScalar)
		lambda_F_etc.Multiply(lambda_F_etc, constant_lambda)
		for k := 0; k < len(lambda); k++ {
			lambda_F_etc.Multiply(lambda_F_etc, ed.NewScalar().Subtract(jScalar, lambda[k]))
		}

		// Fj = F(j), xj = x^j
		Fj := ed.NewScalar()
		xj := ed.NewScalar().Set(oneScalar)
		for k := 0; k < len(Fi); k++ {
			Fj.Add(Fj, ed.NewScalar().Multiply(Fi[k], xj))
			xj.Multiply(xj, jScalar)
		}
		lambda_F_etc.Multiply(lambda_F_etc, Fj)

		// etc = di + ei * rhoi
		etc := ed.NewScalar().MultiplyAdd(ei, rhoi, di)
		lambda_F_etc.Add(lambda_F_etc, etc)

		lambda_F_etc_list[j] = ed.NewScalar().Set(lambda_F_etc)

		// cij_hat = H3(C_i,tin, (lambda_i * F_i)(j)*j + di + ei*rhoi, Ri_hat)
		cij_hat_bytes := TIncrease_H3(C_i_tin, lambda_F_etc, Ri_hat)
		cij_hat, err := ed.NewScalar().SetUniformBytes(cij_hat_bytes[:])
		if err != nil {
			panic(err)
		}

		// sij_hat = cij_hat * sk_i^(0) + ri_hat
		sij_hat := ed.NewScalar().Multiply(cij_hat, secretKeys[ui].sk[0])
		sij_hat.Add(sij_hat, ri_hat)
		sij_hat_list[j] = ed.NewScalar().Set(sij_hat)
	}

	return si, C_i_tin, sij_hat_list, Ri_hat, lambda_F_etc_list
}

func (p *Person) Verify_TIncrease(sjList []*ed.Scalar, C_j_tinList [][]*ed.Point, sji_hatList []*ed.Scalar, Rj_hatList []*ed.Point, lambda_F_etcList []*ed.Scalar) {

	for j := 0; j < len(thresholdSet); j++ {
		// Yi == multiply k=0 to wj-1 C'_jk^(j^k)
		uj := thresholdSet[j]
		jScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(uj, 64))
		if err != nil {
			panic(err)
		}

		left := ed.NewIdentityPoint()
		right := ed.NewIdentityPoint()

		Yj := ed.NewIdentityPoint().Set(publicVerificationShares[uj].Y)
		left.Set(Yj)

		C_j_tin := C_j_tinList[j]

		exponentials := make([]*ed.Scalar, len(C_j_tin))
		exponentials[0], err = ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		if err != nil {
			panic(err)
		}
		for k := 1; k < len(C_j_tinList[j]); k++ {
			exponentials[k] = ed.NewScalar().Multiply(exponentials[k-1], jScalar)
		}

		for k := range C_j_tinList[j] {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(exponentials[k], C_j_tin[k]))
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to Yj")
		}

		// g^sj == Rj * C'_j0^(c * lambda_j(0))
		left.Set(ed.NewIdentityPoint())
		right.Set(ed.NewIdentityPoint())

		sj := sjList[j]

		left = ed.NewGeneratorPoint().ScalarBaseMult(sj)
		Rj := ed.NewIdentityPoint().Set(Rs[j])
		right = ed.NewIdentityPoint().Set(Rj)

		constant_lambda, lambda := participants[uj].Generalized_lagrange_coefficient()
		lambda_zero := ed.NewScalar().Set(constant_lambda)
		for k := range lambda {
			lambda_zero.Multiply(lambda_zero, ed.NewScalar().Negate(lambda[k]))
		}

		right.Add(right, ed.NewIdentityPoint().ScalarMult(ed.NewScalar().Multiply(c, lambda_zero), C_j_tin[0]))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^sj")
		}

		// g^sji_hat == Yj^cji_hat * Rj_hat
		left.Set(ed.NewIdentityPoint())
		right.Set(ed.NewIdentityPoint())

		sji_hat := sji_hatList[j]
		lambda_F_etc := lambda_F_etcList[j]
		Rj_hat := Rj_hatList[j]

		cji_hat_bytes := TIncrease_H3(C_j_tin, lambda_F_etc, Rj_hat)
		cji_hat, err := ed.NewScalar().SetUniformBytes(cji_hat_bytes[:])
		if err != nil {
			panic(err)
		}

		left = ed.NewGeneratorPoint().ScalarBaseMult(sji_hat)
		right = ed.NewIdentityPoint().Set(Rj_hat)
		right.Add(right, ed.NewIdentityPoint().ScalarMult(cji_hat, Yj))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^sji_hat")
		}
	}

	// g^(sum sj) == pk^c * R
	left := ed.NewIdentityPoint()
	right := ed.NewIdentityPoint()

	sum := ed.NewScalar()
	for j := range sjList {
		sum.Add(sum, sjList[j])
	}

	left.Set(ed.NewGeneratorPoint().ScalarBaseMult(sum))

	right.Set(R)
	right.Add(right, ed.NewIdentityPoint().ScalarMult(c, Y))

	if left.Equal(right) == 0 {
		fmt.Println("verification fail to g^sum sj")
	}
}

// lambda_F_etc_list : list of (lambda_j * F_j)(i) * i + dj + ej * rhoj, i : idx of p in thresholdSet
func (p *Person) TIncrease_update_key_pair(lambda_F_etc_list []*ed.Scalar) {
	ui := p.idx
	wi := weights[ui]
	new_sk_list := make([]*ed.Scalar, wi)

	// update sk_i^(0)
	new_sk := ed.NewScalar()
	for j := 0; j < len(lambda_F_etc_list); j++ {
		new_sk.Add(new_sk, lambda_F_etc_list[j])
	}
	new_sk_list[0] = ed.NewScalar().Set(new_sk)

	// update sk_i^(1) ~ sk_i^(wi-1)
	// sk_i^(k) = (x * f(x))^(k)(i), f^(k)(i) = prev sk_i^(k)
	// (x * f(x))^(k)(i) = k*f^(k-1)(i) + i*f^(k)(i)
	iScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
	for k := 1; k < wi; k++ {
		new_sk.Set(ed.NewScalar())
		f_km1 := ed.NewScalar().Set(secretKeys[ui].sk[k-1])
		f_k := ed.NewScalar().Set(secretKeys[ui].sk[k])
		kScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(k, 64))
		new_sk = ed.NewScalar().Multiply(kScalar, f_km1)
		new_sk.Add(new_sk, ed.NewScalar().Multiply(iScalar, f_k))
		new_sk_list[k] = ed.NewScalar().Set(new_sk)
	}
}

func Adapt_TIncrease() {
	// Initialize time measurement map
	tincParticipantTimes = make(map[int]time.Duration)

	Calculate_common_part()

	siList := make([]*ed.Scalar, len(thresholdSet))
	C_i_tinMatrix := make([][]*ed.Point, len(thresholdSet))
	sij_hatMatrix := make([][]*ed.Scalar, len(thresholdSet))
	Ri_hatList := make([]*ed.Point, len(thresholdSet))
	lambda_F_etcMatric := make([][]*ed.Scalar, len(thresholdSet))

	var wg sync.WaitGroup

	// adapt TIncrease - measure individual participant time
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]

			// Start time measurement for individual participant
			startTime := time.Now()

			si, C_i_tin, sij_hat, Ri_hat, lambda_F_etc := participants[idx].TIncrease(i)

			// End time measurement and save
			elapsedTime := time.Since(startTime)
			tincTimesMutex.Lock()
			tincParticipantTimes[idx] = elapsedTime
			tincTimesMutex.Unlock()

			siList[i] = ed.NewScalar().Set(si)
			C_i_tinMatrix[i] = C_i_tin
			sij_hatMatrix[i] = sij_hat
			Ri_hatList[i] = ed.NewIdentityPoint().Set(Ri_hat)
			lambda_F_etcMatric[i] = lambda_F_etc
		}(idx)
	}

	wg.Wait()

	// Print individual participant execution time
	fmt.Println("\n--- Individual Participant TIncrease Execution Time ---")
	for _, idx := range thresholdSet {
		participantName := "Participant"
		if idx == 0 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Alice"
		} else if idx == 1 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Bob"
		}
		fmt.Printf("%s %d (Weight: %d): %v\n", participantName, idx, weights[idx], tincParticipantTimes[idx])
	}
	fmt.Println()

	sji_hatMatrix := Transpose_matrix(sij_hatMatrix)
	lambda_F_etcMatric_tr := Transpose_matrix(lambda_F_etcMatric)

	// Measure TIncrease Verification time
	startVerify := time.Now()

	// Verification is performed in parallel but individual participant time measurement is omitted
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			idx := thresholdSet[i]
			participants[idx].Verify_TIncrease(siList, C_i_tinMatrix, sji_hatMatrix[i], Ri_hatList, lambda_F_etcMatric_tr[i])
		}(idx)
	}

	wg.Wait()

	verifyTime := time.Since(startVerify)
	fmt.Printf("TIncrease verification phase time: %v\n\n", verifyTime)

	// Measure Key Pair Update time
	startUpdate := time.Now()

	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			idx := thresholdSet[i]
			participants[idx].TIncrease_update_key_pair(lambda_F_etcMatric_tr[i])
		}(idx)
	}

	wg.Wait()

	updateTime := time.Since(startUpdate)
	fmt.Printf("TIncrease key update time: %v\n\n", updateTime)
}
