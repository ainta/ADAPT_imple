package adapt

import (
	"fmt"
	"os"
	"strconv"

	ed "filippo.io/edwards25519"
)

// Global values
// N : whole users
var N int

// n : whole users that sum of weights is N
var n int

// w : whole weight (threshold)
var w int

// weights : weight of users
var weights []int

// maxW : maximum weight
var maxW int

// ppN : pairs for pre-processing
var ppN int

// signAgg : sign aggregator (0 ~ n-1 : randomly)
var signAgg int

// msg : signing message
var msg []byte

// availableIdx
var availableIdx int

// thresholdSet : P that participants to sign
var thresholdSet []int

// participants
var participants []Person

// proofs
var proofs []Pi

// commitments
var commitments []Commit

// secret shares
var secretShares []SecretShare

// secret keys
var secretKeys []SecretKey

// public verification shares
var publicVerificationShares []PublicVerificationShare

// group public key
var groupPublicKey *ed.Point

// for pre-processing
// private nonces
var privateNonceLists []PrivateNonceList

// public commits
var publicCommitLists []PublicCommitList

// for sign
// binding factor B
var bindingFactors []IndexAndPublicCommit

// binding values
var bindings []Binding

// group commtiment
var groupCommit *ed.Point

// group challenge
var groupChallenge *ed.Scalar

// partial signatures
var partialSignatures []PartialSignature

// signature commits
var signatureCommits []SignatureCommit

// group signature
var groupSignature Signature

// initialize
func init() {
	// Check basic parameters
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <N> <w> [mode]")
		fmt.Println("  - N: Total number of weights")
		fmt.Println("  - w: Threshold value")
		fmt.Println("  - mode: Weight distribution mode (extreme or uniform, default is uniform)")
		os.Exit(1)
	}

	N, _ = strconv.Atoi(os.Args[1])
	w, _ = strconv.Atoi(os.Args[2])

	// Mode selection (third argument)
	useExtremeWeights := false
	if len(os.Args) > 3 && os.Args[3] == "extreme" {
		useExtremeWeights = true
		fmt.Println("=== Extreme Weight Distribution Mode ===")
	} else {
		fmt.Println("=== Uniform Weight Distribution Mode ===")
	}

	if useExtremeWeights {
		// Extreme weight distribution mode
		// Only use Alice and Bob
		n = 2

		weights = make([]int, n)

		// Alice(index 0) and Bob(index 1) setting
		alice := 0
		bob := 1

		// Give Alice (t-1) weight
		weights[alice] = w - 1

		// Give Bob 1 weight
		weights[bob] = 1

		maxW = weights[alice] // Alice's weight is maximum

		// Only Alice and Bob participate in signing process
		thresholdSet = []int{alice, bob}

		fmt.Printf("Alice (idx %d) Weight: %d\n", alice, weights[alice])
		fmt.Printf("Bob (idx %d) Weight: %d\n", bob, weights[bob])
		fmt.Printf("Total Signing Weight: %d (threshold: %d)\n", weights[alice]+weights[bob], w)
	} else {
		// Uniform weight distribution mode
		// Set n like existing code
		n = (N * 2) / 5

		weights = make([]int, n)

		// Existing uniform weight distribution (1,2,3,4)
		for i := 0; i < n; i += 4 {
			if i < n {
				weights[i] = 1
			}
			if i+1 < n {
				weights[i+1] = 2
			}
			if i+2 < n {
				weights[i+2] = 3
			}
			if i+3 < n {
				weights[i+3] = 4
			}
		}

		maxW = 4

		// Existing code: Randomly select signers set with sum of weights = w
		thresholdSet = Random_int_array(n, w)
	}

	participants = make([]Person, n)
	proofs = make([]Pi, n)
	commitments = make([]Commit, n)
	secretShares = make([]SecretShare, n)
	secretKeys = make([]SecretKey, n)
	publicVerificationShares = make([]PublicVerificationShare, n)
	groupPublicKey = ed.NewIdentityPoint()

	for i := 0; i < n; i++ {
		participants[i] = Person{
			idx:  i,
			poly: make([]*ed.Scalar, w),
		}
	}

	fmt.Println("\n--- Execution Info ---")
	fmt.Println("Total Participants:", n)
	fmt.Println("Total Threshold(Weight):", w)
	fmt.Println("Maximum Weight:", maxW)

	// Print signing participants info
	fmt.Println("\nSigning Participants:")
	totalWeight := 0
	for _, idx := range thresholdSet {
		fmt.Printf("Participant %d (Weight: %d)\n", idx, weights[idx])
		totalWeight += weights[idx]
	}
	fmt.Printf("Signing Participants Total Weight: %d\n", totalWeight)
	fmt.Println()
}
