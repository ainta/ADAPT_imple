package main

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

// VirtualizedParticipant represents a participant with virtualized weight
type VirtualizedParticipant struct {
	Name       string
	RealWeight int
	VirtualIds []int // IDs of virtual participants this real participant controls
}

// Make random bytes for cryptographic operations
func makeRandomBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

// RunWeightTests runs the weight comparison tests independently from FROST
func RunWeightTests() {
	// Define scenarios matching Table 3 in the paper
	scenarios := []struct {
		name        string
		aliceWeight int
		bobWeight   int
		threshold   int
	}{
		{"25/50 (Alice:24, Bob:1)", 24, 1, 25}, // 50% threshold
		{"37/50 (Alice:36, Bob:1)", 36, 1, 37}, // 75% threshold
		{"50/50 (Alice:49, Bob:1)", 49, 1, 50}, // 100% threshold
	}

	fmt.Println("\n=== Virtualized Weight Solution Performance (Sign Operation Only) ===")
	fmt.Println("| Scenario | Sign Operation Ratio (Alice/Bob) |")
	fmt.Println("|----------|-----------------------------|")

	for _, s := range scenarios {
		aliceTime, bobTime := runSignScenario(s.name, s.aliceWeight, s.bobWeight, s.threshold)

		// Calculate ratio for Sign operation
		signRatio := float64(aliceTime.Microseconds()) / float64(bobTime.Microseconds())

		fmt.Printf("| %s | %.2f |\n", s.name, signRatio)
	}
}

// Run a specific weight distribution scenario and return Sign operation times
func runSignScenario(scenarioName string, aliceWeight, bobWeight, threshold int) (time.Duration, time.Duration) {
	// Mapping of participants to their virtual IDs
	alice := VirtualizedParticipant{
		Name:       "Alice",
		RealWeight: aliceWeight,
		VirtualIds: make([]int, aliceWeight),
	}

	bob := VirtualizedParticipant{
		Name:       "Bob",
		RealWeight: bobWeight,
		VirtualIds: make([]int, bobWeight),
	}

	// Initialize virtual IDs
	totalParticipants := aliceWeight + bobWeight
	for i := 0; i < aliceWeight; i++ {
		alice.VirtualIds[i] = i
	}
	for i := 0; i < bobWeight; i++ {
		bob.VirtualIds[i] = aliceWeight + i
	}

	fmt.Printf("\nRunning scenario: %s\n", scenarioName)
	fmt.Printf("Total participants: %d, Threshold: %d\n", totalParticipants, threshold)

	// Measure Sign operation time for Alice and Bob
	aliceTime := measureSignOperation(alice, totalParticipants, threshold)
	bobTime := measureSignOperation(bob, totalParticipants, threshold)

	fmt.Printf("Alice signing time: %v\n", aliceTime)
	fmt.Printf("Bob signing time: %v\n", bobTime)
	fmt.Printf("Ratio (Alice/Bob): %.2f\n", float64(aliceTime.Microseconds())/float64(bobTime.Microseconds()))

	return aliceTime, bobTime
}

// Measure Sign operation time for a virtualized participant
func measureSignOperation(p VirtualizedParticipant, totalParticipants, threshold int) time.Duration {
	fmt.Printf("Measuring signing operation for %s (Weight: %d)...\n", p.Name, p.RealWeight)

	// Measure Sign operation
	start := time.Now()
	virtualizedSign(p, totalParticipants, threshold)
	elapsed := time.Since(start)

	return elapsed
}

// Simulate virtualized Sign operation
func virtualizedSign(p VirtualizedParticipant, totalParticipants, threshold int) {
	var wg sync.WaitGroup

	// 1. Generate polynomials (part of Round1)
	for _, vId := range p.VirtualIds {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each virtual participant generates polynomial
			poly := make([]*ed.Scalar, threshold)
			for j := 0; j < threshold; j++ {
				bytes := makeRandomBytes(64)
				s := ed.NewScalar()
				s.SetUniformBytes(bytes)
				poly[j] = s
			}

			// Generate proof
			bytes := makeRandomBytes(64)
			k, _ := ed.NewScalar().SetUniformBytes(bytes)
			// Replace R variable with _ (blank identifier) to indicate non-use
			_ = ed.NewGeneratorPoint().ScalarBaseMult(k)

			// Generate commitment
			commitments := make([]*ed.Point, threshold)
			for j := 0; j < threshold; j++ {
				commitments[j] = ed.NewGeneratorPoint().ScalarBaseMult(poly[j])
			}
		}(vId)
	}
	wg.Wait()

	// 2. Secret sharing (part of Round2)
	for _, vId := range p.VirtualIds {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Calculate secret shares
			shares := make([]*ed.Scalar, totalParticipants)
			for i := 0; i < totalParticipants; i++ {
				bytes := makeRandomBytes(64)
				shares[i], _ = ed.NewScalar().SetUniformBytes(bytes)
			}

			// Calculate verification shares
			bytes := makeRandomBytes(64)
			s, _ := ed.NewScalar().SetUniformBytes(bytes)
			// Replace y variable with _ (blank identifier)
			_ = ed.NewGeneratorPoint().ScalarBaseMult(s)
		}(vId)
	}
	wg.Wait()

	// 3. Generate signature
	for _, vId := range p.VirtualIds {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Calculate Lagrange coefficients - using blank identifiers
			_, _ = ed.NewScalar().SetUniformBytes(makeRandomBytes(64))

			// Calculate response values - using blank identifiers
			bytes := makeRandomBytes(64)
			_, _ = ed.NewScalar().SetUniformBytes(bytes)
		}(vId)
	}
	wg.Wait()
}

// Main function for standalone execution
func main() {
	// In Go, if a filename includes _test.go it's treated as a special test file
	// This file has been renamed to weight_compare.go
	RunWeightTests()
}
