package frost

import ed "filippo.io/edwards25519"

//////////////////////////////////////
// structures
// sigma = (R, mu)
// proof of knowledge
type Sigma struct {
	R  *ed.Point
	Mu *ed.Scalar
}

// person : information of users
// idx : i of Pi
// poly : (ai0, ai1, ..., ai(t-1))
type Person struct {
	Idx  int
	Poly []*ed.Scalar
}

// commit : commitments values
// t values per user
type Commit struct {
	C []*ed.Point
}

// secret share : secret share values (l, fi(l))
type SecretShare struct {
	Share []*ed.Scalar
}

// public verification share
type PublicVerificationShare struct {
	Y *ed.Point
}

//////// preprocessing
// private nonce : (d, e)
type PrivateNonce struct {
	D *ed.Scalar
	E *ed.Scalar
}

// public commit : (D, E)
type PublicCommit struct {
	D *ed.Point
	E *ed.Point
}

// public commit list : pi publicCommit values per participants
type PublicCommitList struct {
	L []PublicCommit
}

// private nonce list : pi privateNonce, publicCommit values per participants
type PrivateNonceList struct {
	Nonces  []PrivateNonce
	Commits []PublicCommit
}

//////// signing
// B = [(i, Di, Ei) for i in S]
// ordered List
type IndexAndPublicCommit struct {
	Idx int
	DE  PublicCommit
}

// binding value
type Binding struct {
	Rho *ed.Scalar
}

// response value
type Response struct {
	Z *ed.Scalar
}

// signature by aggregator
// R, z
type Signature struct {
	R *ed.Point
	Z *ed.Scalar
}
