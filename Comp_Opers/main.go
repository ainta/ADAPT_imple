package main

import (
	"fmt"
	"time"

	ed "filippo.io/edwards25519"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func main() {
	// total loop for comparison
	loop := 10000

	// get generator of bn254 curve
	_, _, g1, g2 := bn254.Generators()

	// make slice for pairing operation of bn254
	s1 := []bn254.G1Affine{g1}
	s2 := []bn254.G2Affine{g2}

	// get generator of edwards 25519 curve
	g3 := ed.NewGeneratorPoint()

	start := time.Now()
	for i := 0; i < loop; i++ {
		bn254.Pair(s1, s2)
	}
	end := time.Since(start)
	fmt.Println("time for pairing : ", end)

	start = time.Now()
	for i := 0; i < loop; i++ {
		g1.Add(&g1, &g1)
	}
	end = time.Since(start)
	fmt.Println("time for addition over G1 : ", end)

	start = time.Now()
	for i := 0; i < loop; i++ {
		g2.Add(&g2, &g2)
	}
	end = time.Since(start)
	fmt.Println("time for addition over G2 : ", end)

	start = time.Now()
	for i := 0; i < loop; i++ {
		g3.Add(g3, g3)
	}
	end = time.Since(start)
	fmt.Println("time for addition over Ed25519 : ", end)
}
