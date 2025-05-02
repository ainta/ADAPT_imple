package main

import (
	"crypto/rand"
	"crypto/sha512" // Changed to SHA-512 (64-byte output)
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

	// Run each scenario multiple times and calculate average
	numRuns := 5

	for _, s := range scenarios {
		var totalRatio float64 = 0
		var validRuns int = 0

		for i := 0; i < numRuns; i++ {
			aliceTime, bobTime := runSignScenario(s.name, s.aliceWeight, s.bobWeight, s.threshold)

			// Exclude if Bob's time is too short
			if bobTime.Microseconds() < 100 {
				fmt.Printf("  [WARNING] Run %d: Bob's time is too short: %v\n", i+1, bobTime)
				continue
			}

			// Calculate ratio for Sign operation
			signRatio := float64(aliceTime.Microseconds()) / float64(bobTime.Microseconds())
			fmt.Printf("  Run %d: Ratio = %.2f\n", i+1, signRatio)

			totalRatio += signRatio
			validRuns++
		}

		// Display N/A if no valid runs
		var avgRatio string
		if validRuns > 0 {
			avgRatio = fmt.Sprintf("%.2f", totalRatio/float64(validRuns))
		} else {
			avgRatio = "N/A"
		}

		fmt.Printf("| %s | %s |\n", s.name, avgRatio)
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

	if bobTime.Microseconds() > 0 {
		ratio := float64(aliceTime.Microseconds()) / float64(bobTime.Microseconds())
		fmt.Printf("Ratio (Alice/Bob): %.2f\n", ratio)
	} else {
		fmt.Printf("Ratio (Alice/Bob): [UNMEASURABLE - Bob's time is 0]\n")
	}

	return aliceTime, bobTime
}

// Measure Sign operation time for a virtualized participant
func measureSignOperation(p VirtualizedParticipant, totalParticipants, threshold int) time.Duration {
	fmt.Printf("Measuring signing operation for %s (Weight: %d)...\n", p.Name, p.RealWeight)

	// Measure Sign operation - perform more operations for more accurate measurement
	start := time.Now()
	// Increase repetition count to perform more operations per participant
	repeats := 10
	for i := 0; i < repeats; i++ {
		virtualizedSign(p, totalParticipants, threshold)
	}
	elapsed := time.Since(start)

	return elapsed
}

// Simulate virtualized Sign operation with more computational work
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
				// Add more computational work - hash calculation
				data := makeRandomBytes(128)
				for k := 0; k < 10; k++ { // Repeat for more work
					hashResult := sha512.Sum512(data) // Use SHA-512 (64-byte output)
					data = hashResult[:]
				}

				s := ed.NewScalar()
				s.SetUniformBytes(data[:64]) // SHA-512 outputs 64 bytes, so no issue
				poly[j] = s
			}

			// Generate proof
			bytes := makeRandomBytes(128)
			for k := 0; k < 5; k++ { // Repeat for more work
				hashResult := sha512.Sum512(bytes)
				bytes = hashResult[:]
			}

			k, _ := ed.NewScalar().SetUniformBytes(bytes[:64])
			pointR := ed.NewGeneratorPoint().ScalarBaseMult(k)

			// Generate commitment
			commitments := make([]*ed.Point, threshold)
			for j := 0; j < threshold; j++ {
				commitments[j] = ed.NewGeneratorPoint().ScalarBaseMult(poly[j])

				// Additional computation - add points
				for k := 0; k < 5; k++ {
					commitments[j].Add(commitments[j], pointR)
				}
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
				data := makeRandomBytes(128)
				for k := 0; k < 10; k++ {
					hashResult := sha512.Sum512(data)
					data = hashResult[:]
				}

				shares[i], _ = ed.NewScalar().SetUniformBytes(data[:64])
			}

			// Calculate verification shares
			data := makeRandomBytes(128)
			for k := 0; k < 10; k++ {
				hashResult := sha512.Sum512(data)
				data = hashResult[:]
			}

			s, _ := ed.NewScalar().SetUniformBytes(data[:64])
			pointY := ed.NewGeneratorPoint().ScalarBaseMult(s)

			// Additional computation
			for i := 0; i < 10; i++ {
				tmpPoint := ed.NewGeneratorPoint().ScalarBaseMult(shares[i%totalParticipants])
				pointY.Add(pointY, tmpPoint)
			}
		}(vId)
	}
	wg.Wait()

	// 3. Generate signature
	for _, vId := range p.VirtualIds {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Calculate Lagrange coefficients - more work
			data := makeRandomBytes(128)
			for k := 0; k < 10; k++ {
				hashResult := sha512.Sum512(data)
				data = hashResult[:]
			}

			lagrange, _ := ed.NewScalar().SetUniformBytes(data[:64])

			// Calculate response values - more work
			data = makeRandomBytes(128)
			for k := 0; k < 10; k++ {
				hashResult := sha512.Sum512(data)
				data = hashResult[:]
			}

			z, _ := ed.NewScalar().SetUniformBytes(data[:64])

			// Additional computation - scalar operations
			for i := 0; i < 10; i++ {
				tmp := ed.NewScalar().Multiply(lagrange, z)
				z.Add(z, tmp)
			}
		}(vId)
	}
	wg.Wait()
}

// Main function for standalone execution
func main() {
	RunWeightTests()
}
