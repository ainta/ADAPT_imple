package adapt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	ed "filippo.io/edwards25519"
)

type REGOperation string

const (
	REGWIncrease REGOperation = "WIncrease"
	REGWDecrease REGOperation = "WDecrease"
	REGTIncrease REGOperation = "TIncrease"
	REGTDecrease REGOperation = "TDecrease"
)

type regStaleRow struct {
	owner       int
	startOrder  int
	rows        int
	expireEpoch int
}

type REGState struct {
	Epoch       int
	Threshold   int
	AmbientDim  int
	PointOffset int
	Weights     []int

	Corrupted  []bool
	Certifiers []int
	StaleTTL   int

	PublicRows int
	StaleRows  []regStaleRow
	AuditExact bool
}

type REGPhaseTiming struct {
	Compute time.Duration
	Verify  time.Duration
	Update  time.Duration
	Total   time.Duration
}

type REGMetrics struct {
	Operation string
	Target    int
	Delta     int
	Accepted  bool
	Reason    string

	OldEpoch     int
	NewEpoch     int
	OldThreshold int
	NewThreshold int

	OldExposure        int
	FinalExposure      int
	TransientExposure  int
	LiveRows           int
	StaleRows          int
	PublicRows         int
	CertWeight         int
	CertVerified       bool
	ExactFinalRank     int
	ExactTransientRank int

	MetadataGuard  time.Duration
	ExactRankAudit time.Duration
	CertOnline     time.Duration
	CertFull       time.Duration
	Local          REGPhaseTiming
	Total          time.Duration
}

type REGCertificate struct {
	Message    [32]byte
	R          []byte
	Sigma      []byte
	PublicKey  []byte
	Certifiers []int
	Weight     int
}

type REGTightnessMetrics struct {
	Threshold             int
	ConservativeFinalRank int
	ExactFinalRank        int
	ConservativeRejects   bool
	ExactAccepts          bool
}

func REGNewState(corruptOwners []int, staleTTL int) *REGState {
	if staleTTL <= 0 {
		staleTTL = 1
	}
	corrupted := make([]bool, len(weights))
	for _, owner := range corruptOwners {
		if owner >= 0 && owner < len(corrupted) {
			corrupted[owner] = true
		}
	}
	ws := make([]int, len(weights))
	copy(ws, weights)
	return &REGState{
		Epoch:       0,
		Threshold:   w,
		AmbientDim:  w,
		PointOffset: regDefaultPointOffset,
		Weights:     ws,
		Corrupted:   corrupted,
		Certifiers:  append([]int(nil), thresholdSet...),
		StaleTTL:    staleTTL,
	}
}

func REGExactRankTightnessExample() REGTightnessMetrics {
	state := REGSyntheticState(2, []int{1, 1}, []int{0}, 2)
	state.PointOffset = 1
	state.StaleRows = append(state.StaleRows, regStaleRow{
		owner:       0,
		startOrder:  0,
		rows:        1,
		expireEpoch: 2,
	})

	conservative := state.ExposureRank(0)
	exact := state.ExactExposureRank(0)
	return REGTightnessMetrics{
		Threshold:             state.Threshold,
		ConservativeFinalRank: conservative,
		ExactFinalRank:        exact,
		ConservativeRejects:   conservative >= state.Threshold,
		ExactAccepts:          exact < state.Threshold,
	}
}

func REGSyntheticState(threshold int, syntheticWeights []int, corruptOwners []int, staleTTL int) *REGState {
	if staleTTL <= 0 {
		staleTTL = 1
	}
	corrupted := make([]bool, len(syntheticWeights))
	for _, owner := range corruptOwners {
		if owner >= 0 && owner < len(corrupted) {
			corrupted[owner] = true
		}
	}
	ws := append([]int(nil), syntheticWeights...)
	return &REGState{
		Epoch:       0,
		Threshold:   threshold,
		AmbientDim:  threshold,
		PointOffset: 1,
		Weights:     ws,
		Corrupted:   corrupted,
		Certifiers:  allOwners(len(syntheticWeights)),
		StaleTTL:    staleTTL,
	}
}

func allOwners(count int) []int {
	owners := make([]int, count)
	for i := range owners {
		owners[i] = i
	}
	return owners
}

func REGForcePrefixThresholdSet() bool {
	sum := 0
	prefix := make([]int, 0)
	for i := 0; i < len(weights); i++ {
		if sum+weights[i] > w {
			continue
		}
		prefix = append(prefix, i)
		sum += weights[i]
		if sum == w {
			thresholdSet = prefix
			return true
		}
	}
	return false
}

func REGSetAuditPointOffset(offset int) {
	if offset < 0 {
		offset = 0
	}
	// The public ADAPT artifact uses owner indices directly as GLI coordinates.
	// Construction-level audits can set offset=1 to use nonzero Shamir points.
	regDefaultPointOffset = offset
}

var regDefaultPointOffset int

func REGCSVHeader() string {
	return strings.Join([]string{
		"op", "target", "delta", "accepted", "reason",
		"old_epoch", "new_epoch", "old_t", "new_t",
		"old_exposure", "final_exposure", "transient_exposure",
		"live_rows", "stale_rows", "public_rows",
		"cert_weight", "cert_verified", "exact_final_rank", "exact_transient_rank",
		"metadata_guard_ns", "cert_online_ns", "cert_full_ns",
		"local_compute_ns", "local_verify_ns", "local_update_ns", "local_total_ns",
		"total_ns", "exact_rank_audit_ns",
	}, ",")
}

func (m REGMetrics) CSVRow() string {
	return fmt.Sprintf("%s,%d,%d,%t,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%t,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
		m.Operation, m.Target, m.Delta, m.Accepted, quoteCSV(m.Reason),
		m.OldEpoch, m.NewEpoch, m.OldThreshold, m.NewThreshold,
		m.OldExposure, m.FinalExposure, m.TransientExposure,
		m.LiveRows, m.StaleRows, m.PublicRows,
		m.CertWeight, m.CertVerified, m.ExactFinalRank, m.ExactTransientRank,
		m.MetadataGuard.Nanoseconds(), m.CertOnline.Nanoseconds(), m.CertFull.Nanoseconds(),
		m.Local.Compute.Nanoseconds(), m.Local.Verify.Nanoseconds(), m.Local.Update.Nanoseconds(),
		m.Local.Total.Nanoseconds(), m.Total.Nanoseconds(), m.ExactRankAudit.Nanoseconds())
}

func quoteCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	return "\"" + s + "\""
}

func (s *REGState) Clone() *REGState {
	cp := &REGState{
		Epoch:       s.Epoch,
		Threshold:   s.Threshold,
		AmbientDim:  s.AmbientDim,
		PointOffset: s.PointOffset,
		Weights:     append([]int(nil), s.Weights...),
		Corrupted:   append([]bool(nil), s.Corrupted...),
		Certifiers:  append([]int(nil), s.Certifiers...),
		StaleTTL:    s.StaleTTL,
		PublicRows:  s.PublicRows,
		StaleRows:   append([]regStaleRow(nil), s.StaleRows...),
		AuditExact:  s.AuditExact,
	}
	return cp
}

func (s *REGState) Apply(op REGOperation, target int, delta int, certMode string, runLocal bool) REGMetrics {
	if delta <= 0 {
		delta = 1
	}
	startTotal := time.Now()
	metadataStart := time.Now()

	metrics := REGMetrics{
		Operation:    string(op),
		Target:       target,
		Delta:        delta,
		OldEpoch:     s.Epoch,
		OldThreshold: s.Threshold,
		OldExposure:  s.ExposureRank(0),
	}

	post := s.Clone()
	post.Epoch++
	reason := post.applyTransition(op, target, delta)
	if reason != "" {
		metrics.Reason = reason
		metrics.MetadataGuard = time.Since(metadataStart)
		metrics.Total = time.Since(startTotal)
		return metrics
	}
	post.GarbageCollect()

	transientRows := s.conservativeTransientRows(op, target, delta)
	finalExposure := post.ExposureRank(0)
	transientExposure := post.ExposureRank(transientRows)

	metrics.NewEpoch = post.Epoch
	metrics.NewThreshold = post.Threshold
	metrics.FinalExposure = finalExposure
	metrics.TransientExposure = transientExposure
	metrics.LiveRows = post.LiveCorruptedRows()
	metrics.StaleRows = post.StaleCorruptedRows()
	metrics.PublicRows = post.PublicRows

	preDigest := s.digest()
	postDigest := post.digest()
	certWeight := s.certifyingWeight()
	certMsg := regTransitionDigest(preDigest, postDigest, op, target, delta, s.Certifiers, certWeight)
	metrics.CertWeight = certWeight

	if s.AuditExact {
		auditStart := time.Now()
		metrics.ExactFinalRank = post.ExactExposureRank(0)
		metrics.ExactTransientRank = post.ExactExposureRank(transientRows)
		metrics.ExactRankAudit = time.Since(auditStart)
	}

	if certWeight < s.Threshold {
		metrics.Reason = "old epoch certificate cannot reach threshold"
		metrics.MetadataGuard = time.Since(metadataStart)
		metrics.Total = time.Since(startTotal)
		return metrics
	}
	if finalExposure >= post.Threshold {
		metrics.Reason = "final exposure reaches threshold"
		metrics.MetadataGuard = time.Since(metadataStart)
		metrics.Total = time.Since(startTotal)
		return metrics
	}
	if transientExposure >= post.Threshold {
		metrics.Reason = "transient exposure reaches threshold"
		metrics.MetadataGuard = time.Since(metadataStart)
		metrics.Total = time.Since(startTotal)
		return metrics
	}

	metrics.MetadataGuard = time.Since(metadataStart)

	switch certMode {
	case "online":
		var ok bool
		var cert REGCertificate
		cert, metrics.CertOnline, ok = REGIssueCertificate(certMsg, false, s.Certifiers, certWeight)
		ok = ok && s.REGVerifyTransitionCertificate(cert, certMsg)
		metrics.CertVerified = ok
		if !ok {
			metrics.Reason = "old epoch transition certificate verification failed"
			metrics.Total = time.Since(startTotal)
			return metrics
		}
	case "full":
		var ok bool
		var cert REGCertificate
		cert, metrics.CertFull, ok = REGIssueCertificate(certMsg, true, s.Certifiers, certWeight)
		ok = ok && s.REGVerifyTransitionCertificate(cert, certMsg)
		metrics.CertVerified = ok
		if !ok {
			metrics.Reason = "old epoch transition certificate verification failed"
			metrics.Total = time.Since(startTotal)
			return metrics
		}
	case "both":
		var okOnline bool
		var okFull bool
		var onlineCert REGCertificate
		var fullCert REGCertificate
		onlineCert, metrics.CertOnline, okOnline = REGIssueCertificate(certMsg, false, s.Certifiers, certWeight)
		fullCert, metrics.CertFull, okFull = REGIssueCertificate(certMsg, true, s.Certifiers, certWeight)
		okOnline = okOnline && s.REGVerifyTransitionCertificate(onlineCert, certMsg)
		okFull = okFull && s.REGVerifyTransitionCertificate(fullCert, certMsg)
		metrics.CertVerified = okOnline && okFull
		if !metrics.CertVerified {
			metrics.Reason = "old epoch transition certificate verification failed"
			metrics.Total = time.Since(startTotal)
			return metrics
		}
	case "none":
		metrics.CertVerified = false
	default:
		metrics.Reason = "unknown certificate mode"
		metrics.Total = time.Since(startTotal)
		return metrics
	}

	if runLocal {
		metrics.Local = REGRunLocalOperationSilent(op, target)
	}

	*s = *post
	metrics.Accepted = true
	metrics.Reason = "accepted"
	metrics.Total = time.Since(startTotal)
	return metrics
}

func (s *REGState) applyTransition(op REGOperation, target int, delta int) string {
	switch op {
	case REGWIncrease:
		if target < 0 || target >= len(s.Weights) {
			return "invalid weight-increase target"
		}
		s.Weights[target] += delta
	case REGWDecrease:
		if target < 0 || target >= len(s.Weights) {
			return "invalid weight-decrease target"
		}
		if s.Weights[target] < delta {
			return "weight decrease underflows target weight"
		}
		startOrder := s.Weights[target] - delta
		s.Weights[target] -= delta
		s.StaleRows = append(s.StaleRows, regStaleRow{
			owner:       target,
			startOrder:  startOrder,
			rows:        delta,
			expireEpoch: s.Epoch + s.StaleTTL,
		})
	case REGTIncrease:
		s.Threshold += delta
		if s.Threshold > s.AmbientDim {
			s.AmbientDim = s.Threshold
		}
	case REGTDecrease:
		if s.Threshold <= delta {
			return "threshold decrease underflows threshold"
		}
		s.Threshold -= delta
		s.PublicRows += delta
	default:
		return "unknown operation"
	}
	return ""
}

func (s *REGState) conservativeTransientRows(op REGOperation, target int, delta int) int {
	switch op {
	case REGWDecrease:
		return s.corruptThresholdParticipants()
	case REGTDecrease:
		return delta
	}
	return 0
}

func (s *REGState) GarbageCollect() {
	kept := make([]regStaleRow, 0, len(s.StaleRows))
	for _, row := range s.StaleRows {
		if row.expireEpoch > s.Epoch {
			kept = append(kept, row)
		}
	}
	s.StaleRows = kept
}

func (s *REGState) ExposureRank(extraTransientRows int) int {
	return s.PublicRows + s.LiveCorruptedRows() + s.StaleCorruptedRows() + extraTransientRows
}

func (s *REGState) ExactExposureRank(extraTransientRows int) int {
	dim := s.AmbientDim + extraTransientRows
	if dim < s.Threshold+s.PublicRows+extraTransientRows {
		dim = s.Threshold + s.PublicRows + extraTransientRows
	}
	rows := make([][]int64, 0)
	for owner, weight := range s.Weights {
		if !s.isCorrupt(owner) {
			continue
		}
		for order := 0; order < weight; order++ {
			rows = append(rows, regDerivativeRow(owner+s.PointOffset, order, dim))
		}
	}
	for _, stale := range s.StaleRows {
		if !s.isCorrupt(stale.owner) {
			continue
		}
		for j := 0; j < stale.rows; j++ {
			rows = append(rows, regDerivativeRow(stale.owner+s.PointOffset, stale.startOrder+j, dim))
		}
	}
	for j := 0; j < s.PublicRows; j++ {
		pos := s.Threshold + j
		if pos >= dim {
			pos = dim - 1
		}
		rows = append(rows, regBasisRow(pos, dim))
	}
	for j := 0; j < extraTransientRows; j++ {
		pos := s.Threshold + s.PublicRows + j
		if pos >= dim {
			pos = dim - 1
		}
		rows = append(rows, regBasisRow(pos, dim))
	}
	return regMatrixRank(rows, dim)
}

const regRankPrime int64 = 2147483647

func regDerivativeRow(owner int, order int, dim int) []int64 {
	row := make([]int64, dim)
	x := regMod(int64(owner))
	for degree := order; degree < dim; degree++ {
		coeff := regFallingFactorial(degree, order)
		coeff = regMul(coeff, regPow(x, degree-order))
		row[degree] = coeff
	}
	return row
}

func regBasisRow(pos int, dim int) []int64 {
	row := make([]int64, dim)
	if pos >= 0 && pos < dim {
		row[pos] = 1
	}
	return row
}

func regMatrixRank(rows [][]int64, dim int) int {
	if len(rows) == 0 || dim == 0 {
		return 0
	}
	matrix := make([][]int64, len(rows))
	for i := range rows {
		matrix[i] = append([]int64(nil), rows[i]...)
	}

	rank := 0
	for col := 0; col < dim && rank < len(matrix); col++ {
		pivot := -1
		for row := rank; row < len(matrix); row++ {
			if matrix[row][col] != 0 {
				pivot = row
				break
			}
		}
		if pivot == -1 {
			continue
		}
		matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
		inv := regInv(matrix[rank][col])
		for col2 := col; col2 < dim; col2++ {
			matrix[rank][col2] = regMul(matrix[rank][col2], inv)
		}
		for row := 0; row < len(matrix); row++ {
			if row == rank || matrix[row][col] == 0 {
				continue
			}
			factor := matrix[row][col]
			for col2 := col; col2 < dim; col2++ {
				matrix[row][col2] = regSub(matrix[row][col2], regMul(factor, matrix[rank][col2]))
			}
		}
		rank++
	}
	return rank
}

func regFallingFactorial(degree int, order int) int64 {
	res := int64(1)
	for i := 0; i < order; i++ {
		res = regMul(res, int64(degree-i))
	}
	return res
}

func regPow(base int64, exp int) int64 {
	res := int64(1)
	base = regMod(base)
	for exp > 0 {
		if exp&1 == 1 {
			res = regMul(res, base)
		}
		base = regMul(base, base)
		exp >>= 1
	}
	return res
}

func regInv(x int64) int64 {
	return regPow(x, int(regRankPrime-2))
}

func regMod(x int64) int64 {
	x %= regRankPrime
	if x < 0 {
		x += regRankPrime
	}
	return x
}

func regAdd(a, b int64) int64 {
	return regMod(a + b)
}

func regSub(a, b int64) int64 {
	return regMod(a - b)
}

func regMul(a, b int64) int64 {
	return regMod(regMod(a) * regMod(b))
}

func (s *REGState) LiveCorruptedRows() int {
	total := 0
	for owner, weight := range s.Weights {
		if s.isCorrupt(owner) {
			total += weight
		}
	}
	return total
}

func (s *REGState) StaleCorruptedRows() int {
	total := 0
	for _, row := range s.StaleRows {
		if s.isCorrupt(row.owner) {
			total += row.rows
		}
	}
	return total
}

func (s *REGState) isCorrupt(owner int) bool {
	return owner >= 0 && owner < len(s.Corrupted) && s.Corrupted[owner]
}

func (s *REGState) corruptThresholdParticipants() int {
	total := 0
	for _, owner := range thresholdSet {
		if s.isCorrupt(owner) {
			total += s.Weights[owner]
		}
	}
	return total
}

func (s *REGState) certifyingWeight() int {
	return s.weightOf(s.Certifiers)
}

func (s *REGState) digest() [32]byte {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(s.Epoch))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(s.Threshold))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(s.AmbientDim))
	h.Write(buf[:])
	for i, weight := range s.Weights {
		binary.LittleEndian.PutUint64(buf[:], uint64(i))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(weight))
		h.Write(buf[:])
	}
	binary.LittleEndian.PutUint64(buf[:], uint64(s.PublicRows))
	h.Write(buf[:])
	for _, row := range s.StaleRows {
		binary.LittleEndian.PutUint64(buf[:], uint64(row.owner))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(row.startOrder))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(row.rows))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(row.expireEpoch))
		h.Write(buf[:])
	}
	if groupPublicKey != nil {
		h.Write(groupPublicKey.Bytes())
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func regTransitionDigest(pre [32]byte, post [32]byte, op REGOperation, target int, delta int, certifiers []int, certWeight int) [32]byte {
	h := sha256.New()
	h.Write([]byte("REG-ADAPT transition v1"))
	h.Write(pre[:])
	h.Write(post[:])
	h.Write([]byte(op))
	certifierDigest := regCertifierDigest(certifiers)
	h.Write(certifierDigest[:])
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(target))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(delta))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(certWeight))
	h.Write(buf[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func regCertifierDigest(certifiers []int) [32]byte {
	h := sha256.New()
	h.Write([]byte("REG-ADAPT certifiers v1"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(certifiers)))
	h.Write(buf[:])
	for _, owner := range certifiers {
		binary.LittleEndian.PutUint64(buf[:], uint64(owner))
		h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func REGIssueCertificate(message [32]byte, includePreprocessing bool, certifiers []int, certWeight int) (REGCertificate, time.Duration, bool) {
	start := time.Now()
	if includePreprocessing {
		Preprocessing()
	}
	cert := REGSignMessageSilent(message[:], certifiers, certWeight)
	ok := REGVerifyCertificate(cert)
	return cert, time.Since(start), ok
}

func REGMeasureCertificate(includePreprocessing bool) time.Duration {
	message := sha256.Sum256([]byte("REG certificate benchmark"))
	_, elapsed, _ := REGIssueCertificate(message, includePreprocessing, thresholdSet, 0)
	return elapsed
}

func REGRunLocalOperationSilent(op REGOperation, target int) REGPhaseTiming {
	switch op {
	case REGWIncrease:
		return regLocalWIncrease(target)
	case REGWDecrease:
		return regLocalWDecrease(target)
	case REGTIncrease:
		return regLocalTIncrease()
	case REGTDecrease:
		return regLocalTDecrease()
	default:
		return REGPhaseTiming{}
	}
}

func REGSignSilent() {
	message := []byte("ADAPT-TEST")
	REGSignMessageSilent(message, thresholdSet, 0)
}

func REGSignMessageSilent(message []byte, certifiers []int, certWeight int) REGCertificate {
	regThresholdSetMutex.Lock()
	defer regThresholdSetMutex.Unlock()

	oldThresholdSet := append([]int(nil), thresholdSet...)
	thresholdSet = append([]int(nil), certifiers...)
	defer func() {
		thresholdSet = oldThresholdSet
	}()

	Sign_init()
	Compute_binding_factors()
	msg = append([]byte(nil), message...)

	var wg sync.WaitGroup
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			participantIdx := thresholdSet[i]

			Compute_binding()
			Compute_group_commitment()
			Compute_group_challenge()

			constantLambda, lambda := participants[participantIdx].Generalized_lagrange_coefficient()
			skList := secretKeys[participantIdx].sk
			Fi := participants[participantIdx].Compute_Fi(constantLambda, lambda, skList)

			lambdaFZero, _ := ed.NewScalar().SetUniformBytes(Int_to_bytes(1, 64))
			lambdaFZero.Multiply(lambdaFZero, constantLambda)
			for k := range lambda {
				lambdaFZero.Multiply(lambdaFZero, ed.NewScalar().Negate(lambda[k]))
			}
			lambdaFZero.Multiply(lambdaFZero, Fi[0])

			sigmai := participants[participantIdx].Compute_partial_signature(lambdaFZero)
			partialSignatures[participantIdx] = PartialSignature{sigmai}

			Cisig := participants[participantIdx].Compute_signature_commitment(Fi)
			signatureCommits[participantIdx] = SignatureCommit{Cisig}
		}(idx)
	}
	wg.Wait()

	participants[signAgg].Verify_public_verification_share()
	participants[signAgg].Verify_partial_signature()
	participants[signAgg].Compute_aggregated_sign()

	digest := sha256.Sum256(message)
	if len(message) == 32 {
		copy(digest[:], message)
	}
	return REGCertificate{
		Message:    digest,
		R:          append([]byte(nil), groupSignature.R.Bytes()...),
		Sigma:      append([]byte(nil), groupSignature.sigmaPrime.Bytes()...),
		PublicKey:  append([]byte(nil), groupPublicKey.Bytes()...),
		Certifiers: append([]int(nil), certifiers...),
		Weight:     certWeight,
	}
}

var regThresholdSetMutex sync.Mutex

func REGVerifySilent() {
	cert := REGCertificate{
		Message:   sha256.Sum256(msg),
		R:         append([]byte(nil), groupSignature.R.Bytes()...),
		Sigma:     append([]byte(nil), groupSignature.sigmaPrime.Bytes()...),
		PublicKey: append([]byte(nil), groupPublicKey.Bytes()...),
	}
	if len(msg) == 32 {
		copy(cert.Message[:], msg)
	}
	if !REGVerifyCertificate(cert) {
		panic("group signature verification failed")
	}
}

func REGVerifyCertificate(cert REGCertificate) bool {
	R, err := ed.NewIdentityPoint().SetBytes(cert.R)
	if err != nil {
		return false
	}
	sigma, err := ed.NewScalar().SetCanonicalBytes(cert.Sigma)
	if err != nil {
		return false
	}
	Y, err := ed.NewIdentityPoint().SetBytes(cert.PublicKey)
	if err != nil {
		return false
	}

	left := ed.NewGeneratorPoint().ScalarBaseMult(sigma)
	c := Signing_H2(R, cert.Message[:], Y)
	cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
	if err != nil {
		return false
	}
	right := ed.NewIdentityPoint().Set(R)
	right.Add(right, ed.NewIdentityPoint().ScalarMult(cScalar, Y))
	return left.Equal(right) == 1
}

func (s *REGState) REGVerifyTransitionCertificate(cert REGCertificate, expectedMessage [32]byte) bool {
	if cert.Message != expectedMessage {
		return false
	}
	if cert.Weight != s.weightOf(cert.Certifiers) {
		return false
	}
	if cert.Weight < s.Threshold {
		return false
	}
	if !sameIntSlice(cert.Certifiers, s.Certifiers) {
		return false
	}
	if groupPublicKey != nil && string(cert.PublicKey) != string(groupPublicKey.Bytes()) {
		return false
	}
	return REGVerifyCertificate(cert)
}

func (s *REGState) weightOf(owners []int) int {
	total := 0
	for _, owner := range owners {
		if owner >= 0 && owner < len(s.Weights) {
			total += s.Weights[owner]
		}
	}
	return total
}

func sameIntSlice(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func regVerifyCurrentSignatureForAllParticipants() {
	var wg sync.WaitGroup
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			left := ed.NewGeneratorPoint().ScalarBaseMult(groupSignature.sigmaPrime)
			right := ed.NewIdentityPoint().Set(groupSignature.R)

			c := Signing_H2(groupSignature.R, msg, groupPublicKey)
			cScalar, err := ed.NewScalar().SetUniformBytes(c[:])
			if err != nil {
				panic(err)
			}

			right.Add(right, ed.NewIdentityPoint().ScalarMult(cScalar, groupPublicKey))
			if left.Equal(right) == 0 {
				panic("group signature verification failed")
			}
		}(idx)
	}
	wg.Wait()
}

func regLocalWIncrease(alpha int) REGPhaseTiming {
	startTotal := time.Now()
	Calculate_common_part()

	var wg sync.WaitGroup
	siList := make([]*ed.Scalar, len(thresholdSet))
	CiWinMatrix := make([][]*ed.Point, len(thresholdSet))
	siHatList := make([]*ed.Scalar, len(thresholdSet))
	RiHatList := make([]*ed.Point, len(thresholdSet))
	lambdaFWjJList := make([]*ed.Scalar, len(thresholdSet))

	startCompute := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			si, CiWin, siHat, RiHat, lambdaFWjJ := participants[owner].WIncrease(alpha)
			siList[i] = ed.NewScalar().Set(si)
			CiWinMatrix[i] = CiWin
			siHatList[i] = ed.NewScalar().Set(siHat)
			RiHatList[i] = ed.NewIdentityPoint().Set(RiHat)
			lambdaFWjJList[i] = ed.NewScalar().Set(lambdaFWjJ)
		}(idx)
	}
	wg.Wait()
	compute := time.Since(startCompute)

	startVerify := time.Now()
	participants[alpha].Verify_WIncrease(siList, CiWinMatrix, siHatList, RiHatList, lambdaFWjJList)
	verify := time.Since(startVerify)

	return REGPhaseTiming{Compute: compute, Verify: verify, Total: time.Since(startTotal)}
}

func regLocalWDecrease(alpha int) REGPhaseTiming {
	startTotal := time.Now()
	wAlpha := weights[alpha]
	Calculate_common_part()

	CiWdeMatrix := make([][]*ed.Point, len(thresholdSet))
	siList := make([]*ed.Scalar, len(thresholdSet))
	RHatMatrix := make([][]*ed.Point, len(thresholdSet))
	hDerMatrix := make([][][]*ed.Scalar, len(thresholdSet))
	for i := 0; i < len(thresholdSet); i++ {
		hDerMatrix[i] = make([][]*ed.Scalar, len(thresholdSet))
	}
	sHatMatrix := make([][]*ed.Scalar, len(thresholdSet))
	CiWdeHatMatrix := make([][]*ed.Point, len(thresholdSet))

	var wg sync.WaitGroup
	startCompute := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			CiWde, si, RHatList, hDer, sHatList, CiWdeHat := participants[owner].WDecrease(alpha, wAlpha, i)
			siList[i] = ed.NewScalar().Set(si)
			CiWdeMatrix[i] = CiWde
			sHatMatrix[i] = sHatList
			RHatMatrix[i] = RHatList
			hDerMatrix[i] = hDer
			CiWdeHatMatrix[i] = CiWdeHat
		}(idx)
	}
	wg.Wait()
	compute := time.Since(startCompute)

	startVerify := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			participants[owner].Verify_WDecrease(alpha, wAlpha, i, CiWdeMatrix, siList, RHatMatrix, hDerMatrix, sHatMatrix, CiWdeHatMatrix)
		}(idx)
	}
	wg.Wait()
	verify := time.Since(startVerify)

	startUpdate := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			participants[owner].WDecrease_update_key_pair(i, alpha, hDerMatrix)
		}(idx)
	}
	wg.Wait()
	update := time.Since(startUpdate)

	return REGPhaseTiming{Compute: compute, Verify: verify, Update: update, Total: time.Since(startTotal)}
}

func regLocalTIncrease() REGPhaseTiming {
	startTotal := time.Now()
	Calculate_common_part()

	siList := make([]*ed.Scalar, len(thresholdSet))
	CiTinMatrix := make([][]*ed.Point, len(thresholdSet))
	sijHatMatrix := make([][]*ed.Scalar, len(thresholdSet))
	RiHatList := make([]*ed.Point, len(thresholdSet))
	lambdaFEtcMatrix := make([][]*ed.Scalar, len(thresholdSet))

	var wg sync.WaitGroup
	startCompute := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			si, CiTin, sijHat, RiHat, lambdaFEtc := participants[owner].TIncrease(i)
			siList[i] = ed.NewScalar().Set(si)
			CiTinMatrix[i] = CiTin
			sijHatMatrix[i] = sijHat
			RiHatList[i] = ed.NewIdentityPoint().Set(RiHat)
			lambdaFEtcMatrix[i] = lambdaFEtc
		}(idx)
	}
	wg.Wait()
	compute := time.Since(startCompute)

	sjiHatMatrix := Transpose_matrix(sijHatMatrix)
	lambdaFEtcMatrixTR := Transpose_matrix(lambdaFEtcMatrix)

	startVerify := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			participants[owner].Verify_TIncrease(siList, CiTinMatrix, sjiHatMatrix[i], RiHatList, lambdaFEtcMatrixTR[i])
		}(idx)
	}
	wg.Wait()
	verify := time.Since(startVerify)

	startUpdate := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			participants[owner].TIncrease_update_key_pair(lambdaFEtcMatrixTR[i])
		}(idx)
	}
	wg.Wait()
	update := time.Since(startUpdate)

	return REGPhaseTiming{Compute: compute, Verify: verify, Update: update, Total: time.Since(startTotal)}
}

func regLocalTDecrease() REGPhaseTiming {
	startTotal := time.Now()
	agg := thresholdSet[0]
	Calculate_common_part()

	siList := make([]*ed.Scalar, len(thresholdSet))
	CiTdeMatrix := make([][]*ed.Point, len(thresholdSet))
	siHatList := make([]*ed.Scalar, len(thresholdSet))
	RiHatList := make([]*ed.Point, len(thresholdSet))
	muiList := make([]*ed.Scalar, len(thresholdSet))

	var wg sync.WaitGroup
	startCompute := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			si, CiTde, siHat, RiHat, mui := participants[owner].TDecrease(i)
			siList[i] = ed.NewScalar().Set(si)
			CiTdeMatrix[i] = CiTde
			siHatList[i] = ed.NewScalar().Set(siHat)
			RiHatList[i] = ed.NewIdentityPoint().Set(RiHat)
			muiList[i] = ed.NewScalar().Set(mui)
		}(idx)
	}
	wg.Wait()
	compute := time.Since(startCompute)

	startVerify := time.Now()
	aWm1 := participants[agg].Verify_TDecrease(siList, CiTdeMatrix, siHatList, RiHatList, muiList)
	verify := time.Since(startVerify)

	startUpdate := time.Now()
	for idx := 0; idx < len(thresholdSet); idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := thresholdSet[i]
			participants[owner].TDecrease_update_key_pair(aWm1)
		}(idx)
	}
	wg.Wait()
	update := time.Since(startUpdate)

	return REGPhaseTiming{Compute: compute, Verify: verify, Update: update, Total: time.Since(startTotal)}
}
