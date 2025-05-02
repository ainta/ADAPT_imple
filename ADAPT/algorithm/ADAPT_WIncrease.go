package adapt

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// Variables for measuring individual participant time
var wincParticipantTimes map[int]time.Duration
var wincTimesMutex sync.Mutex

// common part
var B []IndexAndPublicCommit
var rhos []Binding
var R *ed.Point
var Rs []*ed.Point
var Y *ed.Point
var c *ed.Scalar

// selection alpha
// alpha : who wants to increase his weight
func Get_exist_alpha() int {
	return thresholdSet[rand.Intn(len(thresholdSet))]
}

// calculate common part
// return : B, rhos, Rs, R, c
func Calculate_common_part() {

	for _ = range thresholdSet {
		// binding factors
		B_ := make([]IndexAndPublicCommit, len(thresholdSet))
		for idx := 0; idx < len(thresholdSet); idx++ {
			i := thresholdSet[idx]
			i_Di_Ei := IndexAndPublicCommit{
				Idx: i,
				DE:  publicCommitLists[i].L[availableIdx],
			}

			B_[idx] = i_Di_Ei
		}

		B = make([]IndexAndPublicCommit, 0)
		B = append(B, B_...)

		// rho values
		rhos_ := make([]Binding, len(thresholdSet))
		for idx := 0; idx < len(thresholdSet); idx++ {
			i := thresholdSet[idx]
			rho_i := Signing_H1(msg, i, B)
			rho, err := ed.NewScalar().SetUniformBytes(rho_i[:])
			if err != nil {
				panic(err)
			}

			rhos_[idx] = Binding{rho}
		}

		rhos = make([]Binding, 0)
		rhos = append(rhos, rhos_...)

		// R
		Rs_ := make([]*ed.Point, len(thresholdSet))
		R_ := ed.NewIdentityPoint()
		for idx := 0; idx < len(thresholdSet); idx++ {
			i := thresholdSet[idx]
			rho := rhos[idx].Rho
			D := publicCommitLists[i].L[availableIdx].D
			E := publicCommitLists[i].L[availableIdx].E

			E_rho := ed.NewGeneratorPoint().ScalarMult(rho, E)

			Ri := ed.NewIdentityPoint().Add(D, E_rho)
			Rs_[idx] = ed.NewIdentityPoint().Set(Ri)

			R_.Add(R_, Ri)
		}

		Rs = make([]*ed.Point, 0)
		Rs = append(Rs, Rs_...)

		R = ed.NewIdentityPoint().Set(R_)

		// c
		Y_ := ed.NewIdentityPoint().Set(groupPublicKey)
		Y = ed.NewIdentityPoint().Set(Y_)

		cBytes := Signing_H2(R_, msg, Y_)
		c_, _ := ed.NewScalar().SetUniformBytes(cBytes[:])
		c = ed.NewScalar().Set(c_)
	}
}

// adapt.WIncrease
// return : si, C_i,win, si_hat, Ri_hat, (lambda*F)^(wj)(j)
func (p *Person) WIncrease(alpha int) (*ed.Scalar, []*ed.Point, *ed.Scalar, *ed.Point, *ed.Scalar) {
	ui := p.idx

	// compute Fi
	constant_lambda, lambda := p.Generalized_lagrange_coefficient()
	skList := secretKeys[ui].sk
	Fi := p.Compute_Fi(constant_lambda, lambda, skList)

	// step 1
	// 1-1 : compute si : si = di + ei * rhoi + c * (lambda_i * Fi)(0)
	lambda_F_zero, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	lambda_F_zero.Multiply(lambda_F_zero, constant_lambda)
	for i := range lambda {
		lambda_F_zero.Multiply(lambda_F_zero, ed.NewScalar().Negate(lambda[i]))
	}
	lambda_F_zero.Multiply(lambda_F_zero, Fi[0])

	di := ed.NewScalar().Set(privateNonceLists[ui].Nonces[availableIdx].d)
	ei := ed.NewScalar().Set(privateNonceLists[ui].Nonces[availableIdx].e)
	rhoi := ed.NewScalar().Set(rhos[ui].Rho)

	si := ed.NewScalar()
	si.Add(si, di)
	si.Add(si, ed.NewScalar().Multiply(ei, rhoi))
	si.Add(si, ed.NewScalar().Multiply(c, lambda_F_zero))

	// 1-2 : compute C_i,win = {C'_i,k} where 0 <= k < wi, C'_i,k=g^bi,k, bi,k = coefficients of Fi
	C_i_win := make([]*ed.Point, len(Fi))

	for i := range Fi {
		C_i_win[i] = ed.NewGeneratorPoint().ScalarBaseMult(Fi[i])
	}

	// step 2
	// 2-1 : compute Ri_hat = g^ri_hat, ri_hat is selected randomly
	bytes := Make_random_bytes(64)
	ri_hat, err := ed.NewScalar().SetUniformBytes(bytes)
	if err != nil {
		panic(err)
	}

	Ri_hat := ed.NewGeneratorPoint().ScalarBaseMult(ri_hat)

	// 2-2 : compute ci_hat = H3(C_i,win, (lambda * F)^(wj)(j), Ri_hat)
	expanded_lambda := Expand_poly(lambda)
	for i := range expanded_lambda {
		expanded_lambda[i].Multiply(expanded_lambda[i], constant_lambda)
	}
	wj := weights[alpha]
	alphaScalar, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(alpha, 64))
	if err != nil {
		panic(err)
	}
	lambda_F_wj_j := Derivation_two_poly_mul(expanded_lambda, Fi, wj, alphaScalar)

	ci_hat_bytes := WIncrease_H3(C_i_win, lambda_F_wj_j, Ri_hat)
	ci_hat, err := ed.NewScalar().SetUniformBytes(ci_hat_bytes[:])
	if err != nil {
		panic(err)
	}

	// 2-3 : compute si_hat = ci_hat * sk_i^(0) + ri_hat
	si_hat := ed.NewScalar().Multiply(ci_hat, secretKeys[ui].sk[0])
	si_hat.Add(si_hat, ri_hat)

	// return : si, C_i,win, si_hat, Ri_hat, (lambda*F)^(wj)(j)
	return si, C_i_win, si_hat, Ri_hat, lambda_F_wj_j
}

// verification to WIncrease
// return new sk_j^(wj+1)
func (p *Person) Verify_WIncrease(siList []*ed.Scalar, C_i_winList [][]*ed.Point, si_hatList []*ed.Scalar, Ri_hatList []*ed.Point, lambda_F_wj_jList []*ed.Scalar) {

	uj := p.idx

	// verify 1,2
	for i := 0; i < len(thresholdSet); i++ {
		ui := thresholdSet[i]

		C_i_win := C_i_winList[i]
		si_hat := si_hatList[i]
		Ri_hat := Ri_hatList[i]
		lambda_F_wj_j := lambda_F_wj_jList[i]

		// Yi == multiply k=0 to wi-1 C'_i,k^(i^k)
		left := ed.NewIdentityPoint()
		right := ed.NewIdentityPoint()

		Yi := ed.NewIdentityPoint().Set(publicVerificationShares[ui].Y)
		left.Set(Yi)

		iScalr, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(ui, 64))
		if err != nil {
			panic(err)
		}

		exponentials := make([]*ed.Scalar, len(C_i_win))
		exponentials[0], err = ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
		if err != nil {
			panic(err)
		}

		for i := 1; i < len(C_i_win); i++ {
			exponentials[i] = ed.NewScalar().Multiply(exponentials[i-1], iScalr)
		}

		for i := range C_i_win {
			right.Add(right, ed.NewIdentityPoint().ScalarMult(exponentials[i], C_i_win[i]))
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail on Yi")
		}

		// g^si_hat == Yi^ci_hat * Ri_hat
		left.Set(ed.NewIdentityPoint())
		right.Set(ed.NewIdentityPoint())

		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(si_hat))

		ci_hat_bytes := WIncrease_H3(C_i_win, lambda_F_wj_j, Ri_hat)
		ci_hat, err := ed.NewScalar().SetUniformBytes(ci_hat_bytes[:])
		if err != nil {
			panic(err)
		}

		right.Set(Ri_hat)
		right.Add(right, ed.NewIdentityPoint().ScalarMult(ci_hat, Yi))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail on g^si_hat")
		}
	}

	// verify 3
	for i := 0; i < len(thresholdSet); i++ {
		ui := thresholdSet[i]
		if ui == uj {
			continue
		}

		si := siList[i]
		C_i_win := C_i_winList[i]

		// g^si == Ri * C'_i,0^(c * lambda_i(0))
		left := ed.NewIdentityPoint()
		right := ed.NewIdentityPoint()

		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(si))

		Ri := ed.NewIdentityPoint().Set(Rs[i])

		constant_lambda, lambda := participants[ui].Generalized_lagrange_coefficient()
		lambda_zero := ed.NewScalar().Set(constant_lambda)
		for i := range lambda {
			lambda_zero.Multiply(lambda_zero, ed.NewScalar().Negate(lambda[i]))
		}

		right.Set(ed.NewIdentityPoint().Add(Ri, ed.NewIdentityPoint().ScalarMult(ed.NewScalar().Multiply(c, lambda_zero), C_i_win[0])))

		if left.Equal(right) == 0 {
			fmt.Println("verification fail on g^si")
		}
	}

	// verify 4
	// g^(sum si) == pk^c * R
	left := ed.NewIdentityPoint()
	right := ed.NewIdentityPoint()

	sum_si := ed.NewScalar()
	for i := range siList {
		sum_si.Add(sum_si, siList[i])
	}

	left.Set(ed.NewGeneratorPoint().ScalarBaseMult(sum_si))

	right.Set(R)
	right.Add(right, ed.NewIdentityPoint().ScalarMult(c, Y))

	if left.Equal(right) == 0 {
		fmt.Println("verification fail on g^(sum si)")
	}

	// verify 5
	// g^(lambda_i * F_i)^(wj)(j) == multiply r=0 to wj (multiply k=r to wi-1 C'_i,k ^ (kPr * j^k))^(wj C r * lambda_i^(wj-r)(j))
	factorialsTmp := make([]int, maxW+1)
	factorialsTmp[0] = 1
	for k := 1; k <= maxW; k++ {
		factorialsTmp[k] = factorialsTmp[k-1] * k
	}

	kPrMatrixTmp := make([][]int, maxW+1)
	for k := 0; k <= maxW; k++ {
		kPrMatrixTmp[k] = make([]int, maxW+1)
		kPrMatrixTmp[k][0] = 1
	}

	for k := 0; k <= maxW; k++ {
		for r := 1; r <= k; r++ {
			kPrMatrixTmp[k][r] = factorialsTmp[k] / factorialsTmp[r-1]
		}
	}

	kCrMatrixTmp := make([][]int, maxW+1)
	for k := 0; k <= maxW; k++ {
		kCrMatrixTmp[k] = make([]int, maxW+1)
		kCrMatrixTmp[k][0] = 1
	}

	for k := 0; k <= maxW; k++ {
		for r := 1; r <= k; r++ {
			kCrMatrixTmp[k][r] = kPrMatrixTmp[k][r] / factorialsTmp[r]
		}
	}

	kPrMatrix := make([][]*ed.Scalar, maxW+1)
	kCrMatrix := make([][]*ed.Scalar, maxW+1)
	for k := 0; k <= maxW; k++ {
		kPrMatrix[k] = make([]*ed.Scalar, maxW+1)
		kCrMatrix[k] = make([]*ed.Scalar, maxW+1)
		for r := 0; r <= k; r++ {
			kPrMatrix[k][r], _ = ed.NewScalar().SetUniformBytes(Int_to_bytes(kPrMatrixTmp[k][r], 64))
			kCrMatrix[k][r], _ = ed.NewScalar().SetUniformBytes(Int_to_bytes(kCrMatrixTmp[k][r], 64))
		}
	}

	jexponentials := make([]*ed.Scalar, maxW+1)
	jScalar, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(uj, 64))
	jexponentials[0] = ed.NewScalar().Set(kPrMatrix[0][0])
	for k := 1; k <= maxW; k++ {
		jexponentials[k] = ed.NewScalar().Multiply(jexponentials[k-1], jScalar)
	}

	wj := weights[uj]

	for i := 0; i < len(thresholdSet); i++ {
		ui := thresholdSet[i]
		if ui == uj {
			continue
		}

		left.Set(ed.NewGeneratorPoint().ScalarBaseMult(lambda_F_wj_jList[i]))
		right.Set(ed.NewIdentityPoint())

		constant_lambda, lambda := participants[ui].Generalized_lagrange_coefficient()
		expand_lambda := Expand_poly(lambda)
		for k := range expand_lambda {
			expand_lambda[k].Multiply(expand_lambda[k], constant_lambda)
		}

		coefficients := Compute_derivation_coefficients(expand_lambda)
		lambda_seq_der := Compute_sequential_derivation(wj, uj, len(expand_lambda), coefficients)

		wi := weights[ui]

		for r := 0; r <= wj; r++ {

			tmp := ed.NewIdentityPoint()
			for k := r; k < wi; k++ {
				tmp.Add(tmp, ed.NewIdentityPoint().ScalarMult(ed.NewScalar().Multiply(kPrMatrix[k][r], jexponentials[k]), C_i_winList[i][k]))
			}

			exp := ed.NewScalar().Set(kCrMatrix[wj][r])
			exp.Multiply(exp, lambda_seq_der[wj-r])

			tmp = ed.NewIdentityPoint().ScalarMult(exp, tmp)
			right.Add(right, tmp)
		}

		if left.Equal(right) == 0 {
			fmt.Println("verification fail to g^(lambda * F)^(wj)(j)")
		}
	}

	// new secret key
	new_sk := ed.NewScalar()
	for i := range lambda_F_wj_jList {
		new_sk.Add(new_sk, lambda_F_wj_jList[i])
	}
}

// adapt.WIncrease
func Adapt_WIncrease() {
	// Initialize time measurement map
	wincParticipantTimes = make(map[int]time.Duration)

	// get alpha
	alpha := Get_exist_alpha()
	Calculate_common_part()

	var wg sync.WaitGroup

	siList := make([]*ed.Scalar, len(thresholdSet))
	C_i_winMatrix := make([][]*ed.Point, len(thresholdSet))
	si_hatList := make([]*ed.Scalar, len(thresholdSet))
	Ri_hatList := make([]*ed.Point, len(thresholdSet))
	lambda_F_wj_jList := make([]*ed.Scalar, len(thresholdSet))

	// adapt WIncrease
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			idx := thresholdSet[i]

			// Start time measurement for individual participant
			startTime := time.Now()

			si, C_i_win, si_hat, Ri_hat, lambda_F_wj_j := participants[idx].WIncrease(alpha)

			// End time measurement and save
			elapsedTime := time.Since(startTime)
			wincTimesMutex.Lock()
			wincParticipantTimes[idx] = elapsedTime
			wincTimesMutex.Unlock()

			siList[i] = ed.NewScalar().Set(si)
			C_i_winMatrix[i] = C_i_win
			si_hatList[i] = ed.NewScalar().Set(si_hat)
			Ri_hatList[i] = ed.NewIdentityPoint().Set(Ri_hat)
			lambda_F_wj_jList[i] = ed.NewScalar().Set(lambda_F_wj_j)
		}(idx)
	}

	wg.Wait()

	// Print execution time
	fmt.Println("\n--- Individual Participant WIncrease Execution Time ---")
	for _, idx := range thresholdSet {
		participantName := "Participant"
		if idx == 0 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Alice"
		} else if idx == 1 && len(thresholdSet) == 2 && weights[0] > weights[1] {
			participantName = "Bob"
		}
		fmt.Printf("%s %d (Weight: %d): %v\n", participantName, idx, weights[idx], wincParticipantTimes[idx])
	}
	fmt.Println()

	// adapt WIncrease verification
	// Measure verification time
	startVerify := time.Now()
	participants[alpha].Verify_WIncrease(siList, C_i_winMatrix, si_hatList, Ri_hatList, lambda_F_wj_jList)
	verifyTime := time.Since(startVerify)

	fmt.Printf("WIncrease verification phase time: %v\n\n", verifyTime)
}
