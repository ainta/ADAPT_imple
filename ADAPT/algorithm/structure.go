package adapt

import ed "filippo.io/edwards25519"

// structures for algorithm
// person : information for users
// idx : index of user
// poly : f_i (w - 1 deg) : (a0, ai, ...)
type Person struct {
	idx  int
	poly []*ed.Scalar
}

// pi = (R, sigma bar)
// proof of knowledge
type Pi struct {
	R        *ed.Point
	sigmaBar *ed.Scalar
}

// commit : commitments values
type Commit struct {
	C []*ed.Point
}

// secret share : secret share value (f_j^(m)(i))
type SecretShare struct {
	Share [][]*ed.Scalar
}

// secret key
type SecretKey struct {
	sk []*ed.Scalar
}

// public verification share
type PublicVerificationShare struct {
	Y *ed.Point
}

//////// preprocessing
// private nonce : (d, e)
type PrivateNonce struct {
	d *ed.Scalar
	e *ed.Scalar
}

// public commit : (D, E)
type PublicCommit struct {
	D *ed.Point
	E *ed.Point
}

// public commit list : pi publicCommit values per users
type PublicCommitList struct {
	L []PublicCommit
}

// private nonce list : pi privateNonce, publicCommit values per users
type PrivateNonceList struct {
	Nonces  []PrivateNonce
	Commits []PublicCommit
}

//////// signing
// B = [(ui, Di, Ei) for i in S]
// ordered List
type IndexAndPublicCommit struct {
	Idx int
	DE  PublicCommit
}

// binding
type Binding struct {
	Rho *ed.Scalar
}

// partial signature (sigma)
type PartialSignature struct {
	sigma *ed.Scalar
}

// signature commit (C_i,sig)
type SignatureCommit struct {
	C []*ed.Point
}

// signature by aggregator
// R, sigma_prime
type Signature struct {
	R          *ed.Point
	sigmaPrime *ed.Scalar
}
