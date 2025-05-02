package adapt

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"sort"

	ed "filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// Binomial distribution (np=1.5)
func Binomial(n int, p float64, w int) int {
	cnt := 0

	for {
		for i := 0; i < n; i++ {
			if mrand.Float64() < p {
				cnt++
			}
		}

		if cnt > 0 && cnt < w {
			break
		}
	}

	return cnt
}

// select random someone
func Select_someone(maxN int) int {
	return mrand.Intn(maxN)
}

// index selection for sum(wi) = w
func Random_int_array(maxIdx int, sumW int) []int {
	perm := mrand.Perm(maxIdx)
	sort.Ints(perm)

	sum := 0
	res := make([]int, 0)

	// the sum of weight of participants = w
	for i := 0; i < len(perm); i++ {
		sum += weights[perm[i]]
		res = append(res, perm[i])
		if sum == sumW {
			break
		} else if sum > sumW {
			res = res[0 : len(res)-1]
		}
	}

	return res
}

// functions for computation
// make random 64 bytes for using the filippo.io lib
func Make_random_bytes(len int) []byte {
	res := make([]byte, len)
	crand.Read(res)
	return res
}

// int to byte slice (little endian)
// int -> uint32 -> byte slice
func Int_to_4bytes(num int) []byte {
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(num))
	return bs
}

// int to byte slice (little endian)
// num -> int32 -> little endian buffer -> copy
func Int_to_bytes(num int, length int) []byte {
	bin := make([]byte, length)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, int32(num))
	copy(bin[:len(buf.Bytes())], buf.Bytes())

	return bin
}

// H0 (sha512)
// H(i, phi, g * ai0, Ri)
// i : idx, phi : context, g^ai0 : point, Ri : R
func Hashing(idx int, str string, point *ed.Point, R *ed.Point) [64]byte {
	res := make([]byte, 0)

	// idx to byte array (little endian)
	bs := Int_to_4bytes(idx)

	res = append(res, bs...)

	// context string to byte array
	res = append(res, []byte(str)...)

	// point (g^ai0) to byte array
	pointBytes := point.Bytes()
	res = append(res, pointBytes...)

	// R to byte array
	RBytes := R.Bytes()
	res = append(res, RBytes...)

	return sha512.Sum512(res)
}

// H1 for signing (sha512)
// H1(l, m, B)
// rho_l = H1(l, m, B)
func Signing_H1(m []byte, l int, B []IndexAndPublicCommit) [64]byte {
	res := make([]byte, 0)

	// m to res
	res = append(res, m...)

	// l to byte array (little endian)
	bs := Int_to_4bytes(l)
	res = append(res, bs...)

	// B to res
	for i := 0; i < len(B); i++ {
		idx := B[i].Idx
		res = append(res, Int_to_4bytes(idx)...)

		DEs := B[i].DE
		res = append(res, DEs.D.Bytes()...)
		res = append(res, DEs.E.Bytes()...)
	}

	return sha512.Sum512(res)
}

// H2 for signing (sha3-512)
// H2(m, R, Y)
func Signing_H2(R *ed.Point, m []byte, Y *ed.Point) [64]byte {
	res := make([]byte, 0)

	res = append(res, R.Bytes()...)
	res = append(res, m...)
	res = append(res, Y.Bytes()...)

	return sha3.Sum512(res)
}

// H3 for WIncrease (sha3-512)
// H3(C_i,win, (lambda * F)^(wj)(j), Ri_hat)
func WIncrease_H3(C []*ed.Point, lambda_F_der *ed.Scalar, Ri_hat *ed.Point) [64]byte {
	res := make([]byte, 0)

	for i := range C {
		res = append(res, C[i].Bytes()...)
	}
	res = append(res, lambda_F_der.Bytes()...)
	res = append(res, Ri_hat.Bytes()...)

	return sha3.Sum512(res)
}

// H3 for TIncrease (sha3-512)
// H3(C_i,tin, (lambda_i * F_i)(j) * j + di + ei * thoi, Ri_hat)
func TIncrease_H3(C []*ed.Point, lambda_F_j_etc *ed.Scalar, Ri_hat *ed.Point) [64]byte {
	res := make([]byte, 0)

	for i := range C {
		res = append(res, C[i].Bytes()...)
	}
	res = append(res, lambda_F_j_etc.Bytes()...)
	res = append(res, Ri_hat.Bytes()...)

	return sha3.Sum512(res)
}

// H3 for WDecrease (sha3-512)
// H3(C_i,wde, {h_i^(k)(j)}, R_ij_hat)
func WDecrease_H3(C_i_wde []*ed.Point, h_j_der []*ed.Scalar, R_ij_hat *ed.Point) [64]byte {
	res := make([]byte, 0)

	for i := range C_i_wde {
		res = append(res, C_i_wde[i].Bytes()...)
	}
	for i := range h_j_der {
		res = append(res, h_j_der[i].Bytes()...)
	}
	res = append(res, R_ij_hat.Bytes()...)

	return sha3.Sum512(res)
}

// H3 for TDecrease (sha3-512)
func TDecrease_H3(C_i_tde []*ed.Point, mu_i *ed.Scalar, R_i_hat *ed.Point) [64]byte {
	res := make([]byte, 0)

	for i := range C_i_tde {
		res = append(res, C_i_tde[i].Bytes()...)
	}
	res = append(res, mu_i.Bytes()...)
	res = append(res, R_i_hat.Bytes()...)

	return sha3.Sum512(res)
}

// fast expoentiation s^num over Field
func Fast_exponentiation(num int, s *ed.Scalar) *ed.Scalar {
	one, err := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
	if err != nil {
		panic(err)
	}

	res := ed.NewScalar().Set(one)
	x := ed.NewScalar().Set(s)

	for num > 0 {
		if num%2 == 1 {
			res.Multiply(res, x)
		}

		x.Multiply(x, x)
		num /= 2
	}

	return res
}

// compute coefficients of 0 ~ max(w_j)-th derivation
// result : coefficients of derivated polynomial
func Compute_derivation_coefficients(poly []*ed.Scalar) [][]*ed.Scalar {
	res := make([][]*ed.Scalar, maxW+1)
	for i := 0; i < len(res); i++ {
		res[i] = make([]*ed.Scalar, len(poly))
	}

	deg := len(poly) - 1

	// pre-compute 0! ~ deg!
	factorials := make([]*ed.Scalar, deg+1)
	one := Int_to_bytes(1, 64)
	oneScalar, err := ed.NewScalar().SetUniformBytes(one)
	if err != nil {
		panic(err)
	}

	// 0! = 1
	// (neg)! = 0
	factorials[0] = ed.NewScalar().Set(oneScalar)

	for i := 1; i <= deg; i++ {
		iBytes := Int_to_bytes(i, 64)
		iScalar, err := ed.NewScalar().SetUniformBytes(iBytes)
		if err != nil {
			panic(err)
		}
		factorials[i] = ed.NewScalar().Multiply(factorials[i-1], iScalar)
	}

	// coefficients for k = 0 ~ max(w_j)-th derivation
	for k := 0; k < (maxW + 1); k++ {
		for j := 0; j <= deg; j++ {
			if k > j {
				res[k][j] = ed.NewScalar()
			} else {
				fac := ed.NewScalar().Multiply(factorials[j], ed.NewScalar().Invert(factorials[j-k]))
				res[k][j] = ed.NewScalar().Multiply(poly[j], fac)
			}
		}
	}

	return res
}

// Compute sequential 0 ~ k-th derivation
// poly : derivated polynomial
// poly's 0 ~ k-th derivation where input is x over edwards curve
func Compute_sequential_derivation(k int, x int, polyLen int, coefficients [][]*ed.Scalar) []*ed.Scalar {
	res := make([]*ed.Scalar, k+1)
	// n-1 = degree poly
	deg := polyLen - 1

	// pre-compute powers
	powers := make([]*ed.Scalar, deg+1)
	one := Int_to_bytes(1, 64)
	oneScalar, err := ed.NewScalar().SetUniformBytes(one)
	if err != nil {
		panic(err)
	}
	powers[0] = ed.NewScalar().Set(oneScalar)

	xBytes := Int_to_bytes(x, 64)
	xScalar, err := ed.NewScalar().SetUniformBytes(xBytes)
	if err != nil {
		panic(err)
	}

	for i := 1; i <= deg; i++ {
		powers[i] = ed.NewScalar().Multiply(powers[i-1], xScalar)
	}

	for i := 0; i <= k; i++ {
		sum := ed.NewScalar()

		// j < i : scalar derivation : 0
		for j := i; j <= deg; j++ {
			sum.Add(sum, ed.NewScalar().Multiply(powers[j-i], coefficients[i][j]))
		}

		// derivation result
		res[i] = ed.NewScalar().Set(sum)
	}

	return res
}

// input : poly1, poly2, y (count for derivation), x : input value
// (poly1 * poly2)^(y)(x) = sum k=0 to y (yCk * poly1^(y-k)(x) * poly2^(k)(x))
func Derivation_two_poly_mul(poly1 []*ed.Scalar, poly2 []*ed.Scalar, y int, x *ed.Scalar) *ed.Scalar {
	res := ed.NewScalar()

	maxLen := len(poly1)
	if maxLen < len(poly2) {
		maxLen = len(poly2)
	}

	// pre-compute 0 ~ maxLen!
	factorials := make([]*ed.Scalar, maxLen+1)
	oneBytes := Int_to_bytes(1, 64)
	oneScalar, _ := ed.NewScalar().SetUniformBytes(oneBytes)
	factorials[0] = ed.NewScalar().Set(oneScalar)
	for i := 1; i <= maxLen; i++ {
		iBytes := Int_to_bytes(i, 64)
		iScalar, _ := ed.NewScalar().SetUniformBytes(iBytes)
		factorials[i] = ed.NewScalar().Multiply(factorials[i-1], iScalar)
	}

	// pre-compute x^0 ~ x^maxLen
	powers := make([]*ed.Scalar, maxLen+1)
	powers[0] = ed.NewScalar().Set(oneScalar)
	for i := 1; i <= maxLen; i++ {
		powers[i] = ed.NewScalar().Multiply(powers[i-1], x)
	}

	// pre-compute coefficients of poly's 0 ~ y-th derivation
	der_poly1 := make([][]*ed.Scalar, y+1)
	for i := 0; i < len(der_poly1); i++ {
		der_poly1[i] = make([]*ed.Scalar, len(poly1))
	}

	der_poly2 := make([][]*ed.Scalar, y+1)
	for i := 0; i < len(der_poly2); i++ {
		der_poly2[i] = make([]*ed.Scalar, len(poly2))
	}

	for k := 0; k <= y; k++ {
		for j := 0; j < len(poly1); j++ {
			// scalar derivation : 0
			if k > j {
				der_poly1[k][j] = ed.NewScalar()
			} else {
				// power to coefficient when derivation
				fac := ed.NewScalar().Multiply(factorials[j], ed.NewScalar().Invert(factorials[j-k]))
				der_poly1[k][j] = ed.NewScalar().Multiply(poly1[j], fac)
			}
		}

		for j := 0; j < len(poly2); j++ {
			// scalar derivation : 0
			if k > j {
				der_poly2[k][j] = ed.NewScalar()
			} else {
				// power to coefficient when derivation
				fac := ed.NewScalar().Multiply(factorials[j], ed.NewScalar().Invert(factorials[j-k]))
				der_poly2[k][j] = ed.NewScalar().Multiply(poly2[j], fac)
			}
		}
	}

	// result of 0 ~ y-th derivation
	res_poly1 := make([]*ed.Scalar, y+1)
	res_poly2 := make([]*ed.Scalar, y+1)

	for i := 0; i <= y; i++ {
		sum_poly1 := ed.NewScalar()
		sum_poly2 := ed.NewScalar()

		// j < i : scalar derivation : 0
		for j := i; j < len(poly1); j++ {
			sum_poly1.Add(sum_poly1, ed.NewScalar().Multiply(powers[j-i], der_poly1[i][j]))
		}
		for j := i; j < len(poly2); j++ {
			sum_poly2.Add(sum_poly2, ed.NewScalar().Multiply(powers[j-i], der_poly2[i][j]))
		}

		res_poly1[i] = ed.NewScalar().Set(sum_poly1)
		res_poly2[i] = ed.NewScalar().Set(sum_poly2)
	}

	// result of derivation of (poly1 * poly2)^(y)(x)
	// (poly1 * poly2)^(y)(x) = sum k=0 to y (yCk * poly1^(y-k)(x) * poly2^(k)(x))
	for k := 0; k <= y; k++ {
		term := ed.NewScalar()
		term.Set(factorials[y])
		term.Multiply(term, ed.NewScalar().Invert(factorials[k]))
		term.Multiply(term, ed.NewScalar().Invert(factorials[y-k]))
		term.Multiply(term, res_poly1[y-k])
		term.Multiply(term, res_poly2[k])
		res.Add(res, term)
	}

	return res
}

// divide and conquer for poly expansion
// input poly : (a0, a1, ..., an) of a0 + a1x + a2x^2 + ... + anx^n
// A(x)*B(x) = A0(x)*B0(x) + (A1(x)*B0(x) + A0(x)*B1(x))*x^(n/2) + (A1(x)*B1(x))*x^n
func Divide_and_conquer_expansion(poly1 []*ed.Scalar, poly2 []*ed.Scalar) []*ed.Scalar {
	maxLen := len(poly1)
	if maxLen < len(poly2) {
		maxLen = len(poly2)
	}

	deg := maxLen - 1

	// divide_deg : base deg
	divide_deg := (deg + 1) / 2

	// divide
	var A0 []*ed.Scalar
	var A1 []*ed.Scalar
	var B0 []*ed.Scalar
	var B1 []*ed.Scalar

	if len(poly1) > divide_deg {
		A0 = make([]*ed.Scalar, divide_deg)
		copy(A0, poly1[:divide_deg])
		A1 = make([]*ed.Scalar, len(poly1)-divide_deg)
		copy(A1, poly1[divide_deg:])
	} else {
		A0 = make([]*ed.Scalar, len(poly1))
		copy(A0, poly1)
		A1 = make([]*ed.Scalar, 0)
	}

	if len(poly2) > divide_deg {
		B0 = make([]*ed.Scalar, divide_deg)
		copy(B0, poly2[:divide_deg])
		B1 = make([]*ed.Scalar, len(poly2)-divide_deg)
		copy(B1, poly2[divide_deg:])
	} else {
		B0 = make([]*ed.Scalar, len(poly2))
		copy(B0, poly2)
		B1 = make([]*ed.Scalar, 0)
	}

	// conquer
	A0B0 := make([]*ed.Scalar, len(A0)+len(B0)-1)
	for i := 0; i < len(A0B0); i++ {
		A0B0[i] = ed.NewScalar()
	}
	for i := 0; i < len(A0); i++ {
		for j := 0; j < len(B0); j++ {
			A0B0[i+j].Add(A0B0[i+j], ed.NewScalar().Multiply(A0[i], B0[j]))
		}
	}

	A0B1 := make([]*ed.Scalar, len(A0)+len(B1)-1)
	for i := 0; i < len(A0B1); i++ {
		A0B1[i] = ed.NewScalar()
	}
	for i := 0; i < len(A0); i++ {
		for j := 0; j < len(B1); j++ {
			A0B1[i+j].Add(A0B1[i+j], ed.NewScalar().Multiply(A0[i], B1[j]))
		}
	}

	A1B0 := make([]*ed.Scalar, len(A1)+len(B0)-1)
	for i := 0; i < len(A1B0); i++ {
		A1B0[i] = ed.NewScalar()
	}
	for i := 0; i < len(A1); i++ {
		for j := 0; j < len(B0); j++ {
			A1B0[i+j].Add(A1B0[i+j], ed.NewScalar().Multiply(A1[i], B0[j]))
		}
	}

	A1B1 := make([]*ed.Scalar, len(A1)+len(B1)-1)
	for i := 0; i < len(A1B1); i++ {
		A1B1[i] = ed.NewScalar()
	}
	for i := 0; i < len(A1); i++ {
		for j := 0; j < len(B1); j++ {
			A1B1[i+j].Add(A1B1[i+j], ed.NewScalar().Multiply(A1[i], B1[j]))
		}
	}

	// A(x)*B(x) = A0(x)*B0(x) + (A1(x)*B0(x) + A0(x)*B1(x))*x^(n/2) + (A1(x)*B1(x))*x^n
	AB := make([]*ed.Scalar, len(poly1)+len(poly2)-1)
	for i := 0; i < len(AB); i++ {
		AB[i] = ed.NewScalar()
	}

	// A0B0
	for i := 0; i < len(A0B0); i++ {
		AB[i].Set(A0B0[i])
	}

	// A1B0 + A0B1
	offset := divide_deg
	for i := 0; i < len(A1B0); i++ {
		AB[i+offset].Add(AB[i+offset], A1B0[i])
	}
	for i := 0; i < len(A0B1); i++ {
		AB[i+offset].Add(AB[i+offset], A0B1[i])
	}

	// A1B1
	offset *= 2
	for i := 0; i < len(A1B1); i++ {
		if i+offset < len(AB) {
			AB[i+offset].Add(AB[i+offset], A1B1[i])
		}
	}

	return AB
}

// computation for lambda
// input : a1,...,an of (x-a1)(x-a2)..(x-an)
func Expand_poly(coeffs []*ed.Scalar) []*ed.Scalar {
	polys := make([][]*ed.Scalar, 0)
	oneBytes := Int_to_bytes(1, 64)
	oneScalar, _ := ed.NewScalar().SetUniformBytes(oneBytes)
	for i := 0; i < len(coeffs); i++ {
		polys = append(polys, []*ed.Scalar{ed.NewScalar().Negate(coeffs[i]), ed.NewScalar().Set(oneScalar)})
	}

	for {
		if len(polys) == 1 {
			if len(polys[0]) != (len(coeffs) + 1) {
				err := errors.New("expansion error")
				panic(err)
			} else {
				return polys[0]
			}
		}

		poly1 := polys[0]
		poly2 := polys[1]

		poly_mul := Divide_and_conquer_expansion(poly1, poly2)
		polys = append(polys, poly_mul)
		polys = polys[2:]
	}
}

// polynomial long division
// A = q * B + r
// over edwards curve
// ex) A, B, q, r : [a0, a1, a2] = a0 + a1 x + a2 x^2
func Divide_poly(A, B []*ed.Scalar) (q, r []*ed.Scalar) {
	if len(B) == 0 {
		return nil, nil
	}

	quotient := make([]*ed.Scalar, len(A))
	remainder := make([]*ed.Scalar, len(A))
	for i := range A {
		quotient[i] = ed.NewScalar()
		remainder[i] = ed.NewScalar().Set(A[i])
	}

	for len(remainder) >= len(B) {
		// ratio of top coefficients
		leader := ed.NewScalar().Multiply(remainder[len(remainder)-1], ed.NewScalar().Invert(B[len(B)-1]))

		// update quotient
		quotient[len(remainder)-len(B)] = ed.NewScalar().Set(leader)

		// update remainder
		for j := range B {
			substractor := ed.NewScalar().Multiply(leader, B[j])
			remainder[len(remainder)-len(B)+j] = ed.NewScalar().Subtract(remainder[len(remainder)-len(B)+j], substractor)
		}

		// remove 0 coefficients
		for (len(remainder) > 0) && (remainder[len(remainder)-1].Equal(ed.NewScalar()) == 1) {
			remainder = remainder[:len(remainder)-1]
		}
	}

	return quotient, remainder
}

// combination by dp
func combination_table(n int) [][]int {
	// dynamic programming table
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// base
	for i := 0; i <= n; i++ {
		dp[i][0] = 1
		dp[i][i] = 1
	}

	// pascal triangle
	for i := 1; i <= n; i++ {
		for j := 1; j <= n; j++ {
			if i < j {
				dp[i][j] = 0
			} else {
				dp[i][j] = dp[i-1][j-1] + dp[i-1][j]
			}
		}
	}

	return dp
}

// Gaussian Elimination
// coefficients : Matrix for Gaussian Elimination
// constants : part for 1 (scalar) of Gaussian Elimination
func Gaussian_elimination(coefficients [][]*ed.Scalar, constants []*ed.Scalar) []*ed.Scalar {
	res := make([]*ed.Scalar, len(constants))
	for i := range res {
		res[i] = ed.NewScalar()
	}

	for i := 0; i < len(coefficients)-1; i++ {
		for j := i + 1; j < len(coefficients); j++ {
			factor := ed.NewScalar().Multiply(coefficients[j][i], ed.NewScalar().Invert(coefficients[i][i]))
			for k := i; k < len(coefficients[j]); k++ {
				substractor := ed.NewScalar().Multiply(factor, coefficients[i][k])
				coefficients[j][k] = ed.NewScalar().Subtract(coefficients[j][k], substractor)
			}

			substractor := ed.NewScalar().Multiply(factor, constants[i])
			constants[j] = ed.NewScalar().Subtract(constants[j], substractor)
		}
	}

	for i := len(coefficients) - 1; i >= 0; i-- {
		sum := constants[i]
		for j := i + 1; j < len(coefficients[i]); j++ {
			substractor := ed.NewScalar().Multiply(coefficients[i][j], res[j])
			sum = ed.NewScalar().Subtract(sum, substractor)
		}
		res[i] = ed.NewScalar().Multiply(sum, ed.NewScalar().Invert(coefficients[i][i]))
	}

	return res
}

// Matrix transpose
func Transpose_matrix(matrix [][]*ed.Scalar) [][]*ed.Scalar {
	rows := len(matrix)
	if rows == 0 {
		return nil
	}

	cols := len(matrix[0])
	if cols == 0 {
		return nil
	}

	result := make([][]*ed.Scalar, cols)
	for i := range result {
		result[i] = make([]*ed.Scalar, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j][i] = ed.NewScalar().Set(matrix[i][j])
		}
	}

	return result
}
