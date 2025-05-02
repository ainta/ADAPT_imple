package frost

import (
	"fmt"
	"os"
	"strconv"

	ed "filippo.io/edwards25519"
)

// global values
// n : whole users
var n int

// t : threshold
var t int

// pi : pairs for pre-processing
var pi int

// signAgg : sign aggregator (0 ~ n-1 : randomly)
var signAgg int

// msg : signing message
var msg []byte

// availableIdx
var availableIdx int

// alpha : t <= alpha <= n
var alpha int

// thresholdSet : participants to sign (S)
var thresholdSet []int

// whole participants
var participants []Person

// proofs
var proofs []Sigma

// commitments
var commitments []Commit

// secret shares
var secretShares []SecretShare

// public verification shares
var publicVerificationShares []PublicVerificationShare

// group public key
var groupPublicKey *ed.Point

// preprocessing
// private nonces
var privateNonceLists []PrivateNonceList

// public commits
var publicCommitLists []PublicCommitList

// signing
// ordered List B
var orderedList []IndexAndPublicCommit

// binding values
var bindings []Binding

// group commtiment
var groupCommit *ed.Point

// group challenge
var groupChallenge *ed.Scalar

// response values
var responses []Response

// group signature
var groupSignature Signature

// flag to indicate if we're in weight test mode
var isWeightTestMode bool = false

// initialization
func init() {
	// Check if enough arguments are provided and not in weight-test mode
	if len(os.Args) <= 1 || os.Args[1] == "weight-test" {
		// Default values for weight test or no arguments
		isWeightTestMode = true
		n = 10 // Default value
		t = 5  // Default value
	} else {
		// Parse n and t from command line arguments
		var err error
		n, err = strconv.Atoi(os.Args[1])
		if err != nil {
			fmt.Println("Invalid value for n:", os.Args[1])
			os.Exit(1)
		}

		t = n // Default t to n
		if len(os.Args) > 2 {
			t, err = strconv.Atoi(os.Args[2])
			if err != nil {
				fmt.Println("Invalid value for t:", os.Args[2])
				os.Exit(1)
			}
		}
	}

	if n < t {
		fmt.Println("n (total participants) < t (thresholds)")
		os.Exit(1)
	}

	// Only initialize these arrays if not in weight test mode
	// or if explicitly required for weight tests
	if !isWeightTestMode {
		participants = make([]Person, n)
		proofs = make([]Sigma, n)
		commitments = make([]Commit, n)
		secretShares = make([]SecretShare, n)
		publicVerificationShares = make([]PublicVerificationShare, n)
		groupPublicKey = ed.NewIdentityPoint()

		for i := 0; i < n; i++ {
			participants[i] = Person{
				Idx:  i,
				Poly: make([]*ed.Scalar, t),
			}
		}

		fmt.Println("total participants : ", n)
		fmt.Println("total thresholds : ", t)
		fmt.Println()
	}
}

// Initialize globals for weight test - this allows us to run the test without
// initializing all global arrays
func InitForWeightTest() {
	isWeightTestMode = true
}

// IsWeightTestMode returns whether we're running in weight test mode
func IsWeightTestMode() bool {
	return isWeightTestMode
}
