package adapt

import (
	"sync"

	ed "filippo.io/edwards25519"
)

// preprocessing_init
func Preprocessing_init() {
	ppN = 1
	privateNonceLists = make([]PrivateNonceList, n)
	publicCommitLists = make([]PublicCommitList, n)
}

// private nonce, public commit values
// privateNonce = {d, e}
// publicCommit = {D, E}
func (p *Person) Compute_preprocessing() (PrivateNonceList, PublicCommitList) {

	privateNonceListResult := PrivateNonceList{
		Nonces:  make([]PrivateNonce, ppN),
		Commits: make([]PublicCommit, ppN),
	}

	publicCommitListResult := PublicCommitList{
		L: make([]PublicCommit, ppN),
	}

	for j := 0; j < ppN; j++ {
		d_ij := Make_random_bytes(64)
		e_ij := Make_random_bytes(64)

		d, err := ed.NewScalar().SetUniformBytes(d_ij)
		if err != nil {
			panic(err)
		}

		e, err := ed.NewScalar().SetUniformBytes(e_ij)
		if err != nil {
			panic(err)
		}

		D := ed.NewGeneratorPoint().ScalarBaseMult(d)
		E := ed.NewGeneratorPoint().ScalarBaseMult(e)

		priv := PrivateNonce{
			d: d,
			e: e,
		}

		pub := PublicCommit{
			D: D,
			E: E,
		}

		privateNonceListResult.Nonces[j] = priv
		privateNonceListResult.Commits[j] = pub

		publicCommitListResult.L[j] = pub
	}

	return privateNonceListResult, publicCommitListResult
}

func Preprocessing() {

	Preprocessing_init()

	var wg sync.WaitGroup

	// preprocessing
	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			privateNonceLists[i], publicCommitLists[i] = participants[i].Compute_preprocessing()
		}(i)
	}

	wg.Wait()
}
