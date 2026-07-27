package submitter

import (
	"testing"

	ctgo "github.com/google/certificate-transparency-go"
)

func makeStrategy(entries ...StrategyMember) []StrategyMember { return entries }

func makeSM(op string, lt LogType) StrategyMember {
	return StrategyMember{Operator: op, LogType: lt, Bucket: NEUTRAL}
}

func dummyResponse() ctgo.AddChainResponse { return ctgo.AddChainResponse{} }

func dummySCT() *ctgo.SignedCertificateTimestamp {
	return &ctgo.SignedCertificateTimestamp{}
}

// --- isQuorumMet ---

func TestIsQuorumMet_SCTCount(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1

	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962), makeSM("B", LOGTYPE_RFC6962))
	qs := newQuorumState()

	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	if qs.isQuorumMet(sr) {
		t.Fatal("quorum should not be met with 1/2 SCTs")
	}

	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())
	if !qs.isQuorumMet(sr) {
		t.Fatal("quorum should be met with 2/2 SCTs")
	}
}

func TestIsQuorumMet_OperatorDiversity(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 2

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("B", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()

	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())
	if qs.isQuorumMet(sr) {
		t.Fatal("quorum should not be met: 2 SCTs but only 1 operator")
	}

	qs.addSuccess(strategy, 2, dummyResponse(), dummySCT())
	if !qs.isQuorumMet(sr) {
		t.Fatal("quorum should be met: 3 SCTs, 2 operators")
	}
}

func TestIsQuorumMet_RequireRFC6962(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	sr.RequireAtLeastOneRFC6962SCT = true

	strategy := makeStrategy(makeSM("A", LOGTYPE_STATIC), makeSM("B", LOGTYPE_RFC6962))
	qs := newQuorumState()

	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	if qs.isQuorumMet(sr) {
		t.Fatal("quorum should not be met: have Static but require RFC6962")
	}

	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())
	if !qs.isQuorumMet(sr) {
		t.Fatal("quorum should be met: have RFC6962")
	}
}

func TestIsQuorumMet_StaticPreferenceDoesNotBlock(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	sr.PreferAtLeastOneStaticSCT = true

	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962))
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	if !qs.isQuorumMet(sr) {
		t.Fatal("PreferAtLeastOneStaticSCT is soft; quorum should still be met")
	}
}

// --- trimToQuorum ---

func TestTrimToQuorum_NoOpWhenExact(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1

	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962), makeSM("A", LOGTYPE_RFC6962))
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())

	qs.trimToQuorum(sr, strategy)
	if len(qs.responses) != 2 {
		t.Fatalf("expected 2 SCTs (no trimming needed), got %d", len(qs.responses))
	}
}

func TestTrimToQuorum_PreservesOperatorDiversity(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 2

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("B", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	for i := range strategy {
		qs.addSuccess(strategy, i, dummyResponse(), dummySCT())
	}

	qs.trimToQuorum(sr, strategy)

	if len(qs.responses) != 2 {
		t.Fatalf("expected 2 SCTs after trim, got %d", len(qs.responses))
	}
	ops := map[string]bool{}
	for _, si := range qs.strategyIndices {
		ops[strategy[si].Operator] = true
	}
	if len(ops) < 2 {
		t.Fatal("trim should preserve operator diversity")
	}
}

func TestTrimToQuorum_PreservesRFC6962Requirement(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1
	sr.RequireAtLeastOneRFC6962SCT = true

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_STATIC),
		makeSM("A", LOGTYPE_STATIC),
		makeSM("A", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	for i := range strategy {
		qs.addSuccess(strategy, i, dummyResponse(), dummySCT())
	}

	qs.trimToQuorum(sr, strategy)

	if len(qs.responses) != 2 {
		t.Fatalf("expected 2 SCTs after trim, got %d", len(qs.responses))
	}
	hasRFC := false
	for _, si := range qs.strategyIndices {
		if strategy[si].LogType == LOGTYPE_RFC6962 {
			hasRFC = true
		}
	}
	if !hasRFC {
		t.Fatal("trim should preserve required RFC6962 SCT")
	}
}

func TestTrimToQuorum_PrefersStaticSCT(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1
	sr.PreferAtLeastOneStaticSCT = true

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_STATIC),
	)
	qs := newQuorumState()
	for i := range strategy {
		qs.addSuccess(strategy, i, dummyResponse(), dummySCT())
	}

	qs.trimToQuorum(sr, strategy)

	if len(qs.responses) != 2 {
		t.Fatalf("expected 2 SCTs after trim, got %d", len(qs.responses))
	}
	hasStatic := false
	for _, si := range qs.strategyIndices {
		if strategy[si].LogType == LOGTYPE_STATIC {
			hasStatic = true
		}
	}
	if !hasStatic {
		t.Fatal("trim should prefer including a Static SCT")
	}
}

func TestTrimToQuorum_RFC6962AndStaticCombined(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1
	sr.RequireAtLeastOneRFC6962SCT = true
	sr.PreferAtLeastOneStaticSCT = true

	// 4 SCTs: 2 Static, 2 RFC6962 — trim to 2 keeping one of each type.
	strategy := makeStrategy(
		makeSM("A", LOGTYPE_STATIC),
		makeSM("A", LOGTYPE_STATIC),
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	for i := range strategy {
		qs.addSuccess(strategy, i, dummyResponse(), dummySCT())
	}

	qs.trimToQuorum(sr, strategy)

	if len(qs.responses) != 2 {
		t.Fatalf("expected 2 SCTs after trim, got %d", len(qs.responses))
	}
	hasRFC, hasStatic := false, false
	for _, si := range qs.strategyIndices {
		if strategy[si].LogType == LOGTYPE_RFC6962 {
			hasRFC = true
		}
		if strategy[si].LogType == LOGTYPE_STATIC {
			hasStatic = true
		}
	}
	if !hasRFC {
		t.Fatal("trim should preserve required RFC6962 SCT")
	}
	if !hasStatic {
		t.Fatal("trim should preserve preferred Static SCT")
	}
}

func TestTrimToQuorum_UpdatesOutcomeForDropped(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())

	qs.trimToQuorum(sr, strategy)

	if len(qs.responses) != 1 {
		t.Fatalf("expected 1 SCT after trim, got %d", len(qs.responses))
	}
	// The dropped entry should have its outcome updated.
	droppedIdx := -1
	for i, sm := range strategy {
		if sm.Outcome != "" {
			droppedIdx = i
			break
		}
	}
	if droppedIdx == -1 {
		t.Fatal("expected one strategy member to have outcome set for dropped entry")
	}
	if strategy[droppedIdx].Outcome != "Submission successful, but not needed for quorum" {
		t.Fatalf("unexpected outcome: %s", strategy[droppedIdx].Outcome)
	}
}

// --- helpsQuorum ---

func TestHelpsQuorum_NeedMoreSCTs(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1

	qs := newQuorumState()
	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962))
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	if !qs.helpsQuorum(sr, makeSM("A", LOGTYPE_RFC6962)) {
		t.Fatal("should help: need more SCTs")
	}
}

func TestHelpsQuorum_NewOperator(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 2

	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962))
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	if !qs.helpsQuorum(sr, makeSM("B", LOGTYPE_RFC6962)) {
		t.Fatal("new operator should help quorum")
	}
	if qs.helpsQuorum(sr, makeSM("A", LOGTYPE_RFC6962)) {
		t.Fatal("same operator should not help: SCT count met, operator already present")
	}
}

func TestHelpsQuorum_RFC6962Needed(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	sr.RequireAtLeastOneRFC6962SCT = true

	qs := newQuorumState()
	// No successes yet — need SCTs AND RFC6962.
	if !qs.helpsQuorum(sr, makeSM("A", LOGTYPE_RFC6962)) {
		t.Fatal("RFC6962 should help: need SCTs")
	}

	strategy := makeStrategy(makeSM("A", LOGTYPE_STATIC))
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	// SCT count met, but no RFC6962 — RFC6962 should still help.
	if !qs.helpsQuorum(sr, makeSM("B", LOGTYPE_RFC6962)) {
		t.Fatal("RFC6962 should help: requirement not yet met")
	}
	if qs.helpsQuorum(sr, makeSM("B", LOGTYPE_STATIC)) {
		t.Fatal("another Static should not help: SCT count met, Static doesn't satisfy RFC6962 requirement")
	}
}

func TestHelpsQuorum_AllMet(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1

	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962))
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	if qs.helpsQuorum(sr, makeSM("B", LOGTYPE_RFC6962)) {
		t.Fatal("should not help: all requirements met")
	}
}

// --- wouldHelp ---

func TestWouldHelp_ExcludesSlowInflight(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 1

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("A", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	// One normal in-flight — optimistically counted, so no more SCTs needed.
	inFlight := map[int]bool{1: true}
	if qs.wouldHelp(sr, strategy[2], strategy, inFlight) {
		t.Fatal("should not help: optimistic count already meets SCT requirement")
	}

	// No in-flight — need another SCT.
	if !qs.wouldHelp(sr, strategy[2], strategy, map[int]bool{}) {
		t.Fatal("should help: still need 1 more SCT")
	}
}

func TestWouldHelp_OperatorDiversityWithInflight(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 2

	strategy := makeStrategy(
		makeSM("A", LOGTYPE_RFC6962),
		makeSM("B", LOGTYPE_RFC6962),
		makeSM("C", LOGTYPE_RFC6962),
	)
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	// B is in-flight — optimistically provides operator "B" and 2nd SCT.
	inFlight := map[int]bool{1: true}
	if qs.wouldHelp(sr, strategy[2], strategy, inFlight) {
		t.Fatal("should not help: optimistic view has 2 SCTs, 2 operators")
	}

	// Without in-flight, C would help (need more SCTs and operators).
	if !qs.wouldHelp(sr, strategy[2], strategy, map[int]bool{}) {
		t.Fatal("should help: need more SCTs and operators")
	}
}

// --- quorumFailureReason ---

func TestQuorumFailureReason_AllUnmet(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 3
	sr.Operators = 2
	sr.RequireAtLeastOneRFC6962SCT = true

	qs := newQuorumState()
	reason := qs.quorumFailureReason(sr)
	if reason == "" {
		t.Fatal("expected non-empty failure reason")
	}
}

func TestQuorumFailureReason_OnlyRFC6962Unmet(t *testing.T) {
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	sr.RequireAtLeastOneRFC6962SCT = true

	strategy := makeStrategy(makeSM("A", LOGTYPE_STATIC))
	qs := newQuorumState()
	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())

	reason := qs.quorumFailureReason(sr)
	if reason == "" {
		t.Fatal("expected failure reason mentioning RFC6962")
	}
}

// --- addSuccess ---

func TestAddSuccess_TracksLogTypes(t *testing.T) {
	strategy := makeStrategy(makeSM("A", LOGTYPE_RFC6962), makeSM("B", LOGTYPE_STATIC))
	qs := newQuorumState()

	qs.addSuccess(strategy, 0, dummyResponse(), dummySCT())
	if !qs.hasRFC6962SCT {
		t.Fatal("should track RFC6962 SCT")
	}
	if qs.hasStaticSCT {
		t.Fatal("should not have Static SCT yet")
	}

	qs.addSuccess(strategy, 1, dummyResponse(), dummySCT())
	if !qs.hasStaticSCT {
		t.Fatal("should track Static SCT")
	}
	if len(qs.operators) != 2 {
		t.Fatalf("expected 2 operators, got %d", len(qs.operators))
	}
}
