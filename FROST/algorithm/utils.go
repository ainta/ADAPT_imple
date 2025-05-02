package frost

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"

	ed "filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// ////////////////////////////////////
// functions for algorithm
// 64 bytes value for using filippo.io lib
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

// H0 (sha256)
func Hashing(idx int, context string, point *ed.Point, R *ed.Point) [64]byte {
	// H(i, phi, g * ai0, Ri)
	// i : idx, phi : context, g^ai0 : point, Ri : R
	res := make([]byte, 0)

	// idx to byte array (little endian)
	bs := Int_to_4bytes(idx)

	res = append(res, bs...)

	// context string to byte array
	res = append(res, []byte(context)...)

	// point (g^ai0) to byte array
	pointBytes := point.Bytes()
	res = append(res, pointBytes...)

	// R to byte array
	RBytes := R.Bytes()
	res = append(res, RBytes...)

	return sha512.Sum512(res)
}

// H1 for signing (sha512)
func Signing_H1(l int, m []byte, B []IndexAndPublicCommit) [64]byte {
	// H1(l, m, B)
	// rho_l = H1(l, m, B)

	res := make([]byte, 0)

	// l to byte array (little endian)
	bs := Int_to_4bytes(l)
	res = append(res, bs...)

	// m to res
	res = append(res, m...)

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
func Signing_H2(R *ed.Point, Y *ed.Point, m []byte) [64]byte {
	// H2(R, Y, m)
	// challenge c = H2(R, Y, m)
	res := make([]byte, 0)

	res = append(res, R.Bytes()...)
	res = append(res, Y.Bytes()...)
	res = append(res, m...)

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
