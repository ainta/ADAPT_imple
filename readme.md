# Implementation of ADAPT and FROST

## Env
- Go : 1.21
- Field : edwards 25519 (https://pkg.go.dev/filippo.io/edwards25519)

## Algorithms
- FROST (https://eprint.iacr.org/2020/852)
- ADAPT (ours)

## Usage

Go version >= 1.17 (for edwards 25519 curve lib)

### Package installation (for Curve and Hash)

```bash
git clone https://github.com/hobin-pet/ADAPT
go get -u filippo.io/edwards25519
go get -u golang.org/x/crypto
```

### Package adaptation

```bash
go mod tidy
```

### Execute codes

```bash
# Standard execution with n=100, t=50
go run ADAPT/main.go 100 50
go run FROST/main.go 100 50

# Execute with extreme weight distribution (Alice has most of the weight)
go run ADAPT/main.go 100 50 extreme

# Execute FROST weight virtualization performance test
go run FROST/algorithm/weight_compare_improved.go
```

In the above bash codes:
- The n and t (threshold for FROST and ADAPT) are 100, 50.
- The "extreme" parameter creates an extreme condition where one participant (Alice) holds almost all weight.
- The weight_compare_improved.go file runs tests to analyze FROST performance in virtualization scenarios.

If you want to change the values (n, t), modify the arguments where the first is n and second is t of threshold for FROST and ADAPT, respectively.

The result is total execution time (because the networking is not considered), and it is stored to ADAPT_result.txt and FROST_result.txt when you run `run.sh`

### Result Interpretation

The average result of users is below:

- result / n (when keygen(round1 + round2) and pre-processing of ADAPT, FROST)
- result / t (when sign of FROST)
- result / p (when sign and functionality(WIncrease, TIncrease, WDecrease, TDecrease) of ADAPT)

Where:
- n : # of users of FROST and ADAPT. (In ADAPT case, the sum of weights of users is n, and in FROST case, the weight of each user is just 1.)
- t : # of participants of FROST. (i.e. threshold is t.)
- p : # of participants of ADAPT that configure threshold. (i.e. the sum of weights of participants is t.)

## Comp_Opers Directory: Implementation for comparison of pairing and addition operations

### Env
- Go : 1.21
- Field : BN254 (github.com/consensys/gnark-crypto/ecc/bn254), edwards 25519 

### Usage

Go version >= 1.19 (for gnark-crypto lib)

#### Package installation

```bash
go get github.com/consensys/gnark-crypto/ecc/bn254
```

#### Package adaptation

```bash
go mod tidy
```

#### Execute codes

```bash
go run Comp_Opers/main.go
```

If you run the above command, you can check 10000 times pairing and addition of generator of each curve.