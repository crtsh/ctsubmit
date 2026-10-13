package submitter

import (
	"fmt"
	"strings"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
)

// submissionEvent represents an event from an in-flight submission goroutine.
type submissionEvent struct {
	strategyIdx int
	eventType   submissionEventType
	response    ctgo.AddChainResponse
	sct         *ctgo.SignedCertificateTimestamp
	outcome     string
	timeTaken   time.Duration
}

type submissionEventType int

const (
	eventSuccess submissionEventType = iota
	eventFailure
	eventTryNext
	eventSlow
)

// quorumState tracks progress toward achieving a compliant quorum of SCTs.
type quorumState struct {
	responses       []ctgo.AddChainResponse
	scts            []*ctgo.SignedCertificateTimestamp
	operators       map[string]bool
	hasRFC6962SCT   bool
	hasStaticSCT    bool
	strategyIndices []int // indices into strategy for each successful response
}

func newQuorumState() *quorumState {
	return &quorumState{
		operators: make(map[string]bool),
	}
}

func (qs *quorumState) addSuccess(strategy []StrategyMember, strategyIdx int, response ctgo.AddChainResponse, sct *ctgo.SignedCertificateTimestamp) {
	qs.responses = append(qs.responses, response)
	qs.scts = append(qs.scts, sct)
	qs.strategyIndices = append(qs.strategyIndices, strategyIdx)

	sm := strategy[strategyIdx]
	qs.operators[sm.Operator] = true
	if sm.LogType == LOGTYPE_RFC6962 {
		qs.hasRFC6962SCT = true
	}
	if sm.LogType == LOGTYPE_STATIC {
		qs.hasStaticSCT = true
	}
}

func (qs *quorumState) isQuorumMet(sr *SubmissionRequest) bool {
	if len(qs.responses) < sr.SCTs {
		return false
	}
	if len(qs.operators) < sr.Operators {
		return false
	}
	if sr.RequireAtLeastOneRFC6962SCT && !qs.hasRFC6962SCT {
		return false
	}
	// PreferAtLeastOneStaticSCT is a soft preference, not a hard requirement for quorum.
	return true
}

func (qs *quorumState) quorumFailureReason(sr *SubmissionRequest) string {
	var reasons []string
	if len(qs.responses) < sr.SCTs {
		reasons = append(reasons, fmt.Sprintf("need %d SCTs but got %d", sr.SCTs, len(qs.responses)))
	}
	if len(qs.operators) < sr.Operators {
		reasons = append(reasons, fmt.Sprintf("need %d distinct operators but got %d", sr.Operators, len(qs.operators)))
	}
	if sr.RequireAtLeastOneRFC6962SCT && !qs.hasRFC6962SCT {
		reasons = append(reasons, "require at least one RFC6962 SCT but got none")
	}
	return strings.Join(reasons, "; ")
}

// trimToQuorum reduces the collected SCTs to exactly sr.SCTs, selecting a subset
// that still satisfies quorum requirements. Excess entries have their strategy
// outcome updated. This is a no-op if the count is already correct.
func (qs *quorumState) trimToQuorum(sr *SubmissionRequest, strategy []StrategyMember) {
	if len(qs.responses) <= sr.SCTs {
		return
	}

	selected := make([]bool, len(qs.responses))
	count := 0

	// Ensure operator diversity: pick one entry per unique operator.
	seenOperators := make(map[string]bool)
	for i, si := range qs.strategyIndices {
		if count >= sr.SCTs {
			break
		}
		op := strategy[si].Operator
		if !seenOperators[op] {
			seenOperators[op] = true
			selected[i] = true
			count++
		}
	}

	// Ensure required RFC6962 coverage: if no RFC6962 SCT was selected, swap one in.
	if sr.RequireAtLeastOneRFC6962SCT {
		has := false
		for i, si := range qs.strategyIndices {
			if selected[i] && strategy[si].LogType == LOGTYPE_RFC6962 {
				has = true
				break
			}
		}
		if !has {
			// Find an unselected RFC6962 entry to add.
			for i, si := range qs.strategyIndices {
				if !selected[i] && strategy[si].LogType == LOGTYPE_RFC6962 {
					selected[i] = true
					count++
					break
				}
			}
			// If we now exceed sr.SCTs, drop a non-RFC6962 entry.
			if count > sr.SCTs {
				for i := len(qs.responses) - 1; i >= 0; i-- {
					if !selected[i] {
						continue
					}
					if strategy[qs.strategyIndices[i]].LogType != LOGTYPE_RFC6962 && qs.canDropSafely(i, selected, strategy, sr) {
						selected[i] = false
						count--
						break
					}
				}
			}
		}
	}

	// Prefer at least one Static SCT: if none was selected, swap one in.
	if sr.PreferAtLeastOneStaticSCT {
		has := false
		for i, si := range qs.strategyIndices {
			if selected[i] && strategy[si].LogType == LOGTYPE_STATIC {
				has = true
				break
			}
		}
		if !has {
			for i, si := range qs.strategyIndices {
				if !selected[i] && strategy[si].LogType == LOGTYPE_STATIC {
					selected[i] = true
					count++
					break
				}
			}
			// If we now exceed sr.SCTs, drop a non-required entry.
			if count > sr.SCTs {
				for i := len(qs.responses) - 1; i >= 0; i-- {
					if !selected[i] {
						continue
					}
					si := qs.strategyIndices[i]
					// Don't drop an RFC6962 SCT if it's the only one and it's required.
					if sr.RequireAtLeastOneRFC6962SCT && strategy[si].LogType == LOGTYPE_RFC6962 {
						onlyRFC6962 := true
						for j, sj := range qs.strategyIndices {
							if j != i && selected[j] && strategy[sj].LogType == LOGTYPE_RFC6962 {
								onlyRFC6962 = false
								break
							}
						}
						if onlyRFC6962 {
							continue
						}
					}
					if strategy[si].LogType != LOGTYPE_STATIC && qs.canDropSafely(i, selected, strategy, sr) {						selected[i] = false
						count--
						break
					}
				}
			}
		}
	}

	// Fill remaining slots in order.
	for i := range qs.responses {
		if count >= sr.SCTs {
			break
		}
		if !selected[i] {
			selected[i] = true
			count++
		}
	}

	// Rebuild the quorum state with only the selected entries.
	var responses []ctgo.AddChainResponse
	var scts []*ctgo.SignedCertificateTimestamp
	var strategyIndices []int
	for i := range qs.responses {
		if selected[i] {
			responses = append(responses, qs.responses[i])
			scts = append(scts, qs.scts[i])
			strategyIndices = append(strategyIndices, qs.strategyIndices[i])
		} else {
			strategy[qs.strategyIndices[i]].Outcome = "Submission successful, but not needed for quorum"
		}
	}
	qs.responses = responses
	qs.scts = scts
	qs.strategyIndices = strategyIndices
}

// canDropSafely returns true if dropping the SCT at dropIdx would still leave enough unique operators to satisfy the submission request.
func (qs *quorumState) canDropSafely(dropIdx int, selected []bool, strategy []StrategyMember, sr *SubmissionRequest) bool {
	droppedOp := strategy[qs.strategyIndices[dropIdx]].Operator
	for j, sj := range qs.strategyIndices {
		if j != dropIdx && selected[j] && strategy[sj].Operator == droppedOp {
			return true
		}
	}

	// If the dropped operator was unique, we must ensure the remaining selected operators are sufficient.
	// We use a map-based O(N) approach to calculate the total unique operators remaining, preventing O(N^3) scaling.
	seen := make(map[string]bool)
	totalUnique := 0
	for j, sj := range qs.strategyIndices {
		if j != dropIdx && selected[j] {
			op := strategy[sj].Operator
			if !seen[op] {
				seen[op] = true
				totalUnique++
			}
		}
	}

	return totalUnique >= sr.Operators
}

// helpsQuorum returns true if the given strategy member would contribute toward
// meeting at least one quorum requirement that is not yet satisfied.
func (qs *quorumState) helpsQuorum(sr *SubmissionRequest, sm StrategyMember) bool {
	if len(qs.responses) < sr.SCTs {
		return true
	}
	if len(qs.operators) < sr.Operators && !qs.operators[sm.Operator] {
		return true
	}
	if sr.RequireAtLeastOneRFC6962SCT && !qs.hasRFC6962SCT && sm.LogType == LOGTYPE_RFC6962 {
		return true
	}
	if sr.PreferAtLeastOneStaticSCT && !qs.hasStaticSCT && sm.LogType == LOGTYPE_STATIC {
		return true
	}
	return false
}

// wouldHelp returns true if the given strategy member could contribute toward
// meeting the remaining quorum requirements, assuming all normal (non-slow)
// in-flight submissions will succeed.  Slow in-flight submissions are excluded
// from the optimistic view because the try-next mechanism exists precisely
// because they are unreliable.
func (qs *quorumState) wouldHelp(sr *SubmissionRequest, sm StrategyMember, strategy []StrategyMember, inFlightIndices map[int]bool) bool {
	// Build an optimistic view counting only normal in-flight submissions as successes.
	optimisticSCTs := len(qs.responses) + len(inFlightIndices)
	optimisticOperators := make(map[string]bool, len(qs.operators)+len(inFlightIndices))
	for k := range qs.operators {
		optimisticOperators[k] = true
	}
	optimisticRFC6962 := qs.hasRFC6962SCT
	optimisticStatic := qs.hasStaticSCT
	for idx := range inFlightIndices {
		ifSm := strategy[idx]
		optimisticOperators[ifSm.Operator] = true
		if ifSm.LogType == LOGTYPE_RFC6962 {
			optimisticRFC6962 = true
		}
		if ifSm.LogType == LOGTYPE_STATIC {
			optimisticStatic = true
		}
	}

	needMoreSCTs := optimisticSCTs < sr.SCTs
	needMoreOperators := len(optimisticOperators) < sr.Operators
	needRFC6962 := sr.RequireAtLeastOneRFC6962SCT && !optimisticRFC6962
	preferStatic := sr.PreferAtLeastOneStaticSCT && !optimisticStatic

	if needMoreSCTs {
		return true
	}
	if needMoreOperators && !optimisticOperators[sm.Operator] {
		return true
	}
	if needRFC6962 && sm.LogType == LOGTYPE_RFC6962 {
		return true
	}
	if preferStatic && sm.LogType == LOGTYPE_STATIC {
		return true
	}

	return false
}
