package pki

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/crtsh/ctloglists"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
)

type ValidateChainCacheMap map[[sha256.Size]byte]bool

var logValidateChainCacheMap map[[sha256.Size]byte]ValidateChainCacheMap
var logValidateChainCacheMutex sync.RWMutex

func init() {
	logValidateChainCacheMap = make(map[[sha256.Size]byte]ValidateChainCacheMap)
	for logID := range ctloglists.LogAcceptedRootsMap {
		logValidateChainCacheMap[logID] = make(ValidateChainCacheMap)
	}
}

func cachedValidateChainResult(logID, chainSHA256 [sha256.Size]byte) (bool, bool) {
	logValidateChainCacheMutex.RLock()
	defer logValidateChainCacheMutex.RUnlock()

	validateChainCacheMap, ok := logValidateChainCacheMap[logID]
	if !ok {
		return false, false
	}
	chainIsValid, ok := validateChainCacheMap[chainSHA256]
	return chainIsValid, ok
}

func cacheValidateChainResult(logID, chainSHA256 [sha256.Size]byte, chainIsValid bool) {
	logValidateChainCacheMutex.Lock()
	defer logValidateChainCacheMutex.Unlock()

	validateChainCacheMap, ok := logValidateChainCacheMap[logID]
	if !ok {
		return
	}
	validateChainCacheMap[chainSHA256] = chainIsValid
}

func ValidateChain(logID [sha256.Size]byte, submittedChain [][]byte, logTemporalInterval *loglist3.TemporalInterval) bool {
	var chainSHA256 [sha256.Size]byte
	var chainIsValid, ok bool

	if len(submittedChain) > 1 { // Don't use the cache when there's no chain.
		// Check if ValidateChain has already been called for this chain of CA certificates / this log.
		// The cache key covers only the non-leaf certs (submittedChain[1:]) because many distinct leaf
		// certificates share the same issuer chain; caching the full chain would cause a miss on every
		// unique leaf, defeating the purpose of the cache.
		// The log's temporal interval is not included because the cache is already partitioned by logID
		// and each log has a fixed temporal interval.
		chainSHA256 = sha256.Sum256(bytes.Join(submittedChain[1:], nil))
		chainIsValid, ok = cachedValidateChainResult(logID, chainSHA256)
	}

	if !ok { // Cache miss or not used.
		// Validate the chain against the accepted roots of this log.
		if ll, ok2 := ctloglists.LogAcceptedRootsMap[logID]; ok2 {
			var start, end *time.Time
			if logTemporalInterval != nil {
				start = &logTemporalInterval.StartInclusive
				end = &logTemporalInterval.EndExclusive
			}
			cvo := ctfe.NewCertValidationOpts(ctloglists.AcceptedRootsMap[ll], time.Now(), false, false, start, end, false, nil)
			_, err := ctfe.ValidateChain(submittedChain, cvo)
			chainIsValid = (err == nil)
			if len(submittedChain) > 1 {
				cacheValidateChainResult(logID, chainSHA256, chainIsValid)
			}
		} else {
			// We have no accepted roots for this log (e.g. it comes from a custom test log list),
			// so let the submission proceed and let the log itself decide.
			chainIsValid = true
		}
	}
	return chainIsValid
}
