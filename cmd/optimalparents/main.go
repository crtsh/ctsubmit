package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	_ "github.com/crtsh/ccadb_data" // Blank import to ensure it appears in build info for module cache lookup.
	"github.com/crtsh/ctloglists"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/google/certificate-transparency-go/loglist3"
)

// certInfo holds a parsed certificate with its raw DER bytes and SHA-256 hash.
type certInfo struct {
	cert   *x509.Certificate
	raw    []byte
	sha256 [sha256.Size]byte
}

// logGroup represents a set of logs sharing the same accepted roots.
type logGroup struct {
	rootsHash [sha256.Size]byte
	count     int
}

func main() {
	// Step 1: Load CCADB certificates from the ccadb_data module's cmd/ski_spki/data directory.
	fmt.Println("Loading CCADB certificates...")
	allCerts := loadCCADBCerts()
	fmt.Printf("Loaded %d certificates\n", len(allCerts))

	// Build index by SubjectKeyId (hex-encoded).
	certsBySKI := make(map[string][]*certInfo)
	for _, ci := range allCerts {
		if len(ci.cert.SubjectKeyId) > 0 {
			ski := hex.EncodeToString(ci.cert.SubjectKeyId)
			certsBySKI[ski] = append(certsBySKI[ski], ci)
		}
	}

	// Step 2: Accepted roots are loaded automatically by the loglists package init().

	// Precompute: for each accepted roots pool, build a set of root cert SHA-256 hashes.
	rootHashSets := make(map[[sha256.Size]byte]map[[sha256.Size]byte]bool)
	for poolHash, pool := range ctloglists.AcceptedRootsMap {
		hashSet := make(map[[sha256.Size]byte]bool)
		for _, cert := range pool.RawCertificates() {
			hashSet[sha256.Sum256(cert.Raw)] = true
		}
		rootHashSets[poolHash] = hashSet
	}

	// Log list contexts, loaded by loglists.init().
	contexts := [4]*loglist3.LogList{
		loglists.UsableTLSLogs,
		loglists.ActiveTLSLogs,
		loglists.TestTLSLogs,
		loglists.UsableBIMILogs,
	}
	contextNames := [4]string{"Usable TLS", "Active TLS", "Test TLS", "Usable BIMI"}

	// Precompute: for each context, group logs by accepted roots hash.
	var contextLogGroups [4][]logGroup
	for i, ctx := range contexts {
		groups := make(map[[sha256.Size]byte]int)
		forEachLog(ctx, func(logID [sha256.Size]byte) {
			if rootsHash, ok := ctloglists.LogAcceptedRootsMap[logID]; ok {
				groups[rootsHash]++
			}
		})
		for rh, cnt := range groups {
			contextLogGroups[i] = append(contextLogGroups[i], logGroup{rootsHash: rh, count: cnt})
		}
		total := 0
		for _, g := range contextLogGroups[i] {
			total += g.count
		}
		fmt.Printf("Context %q: %d logs in %d root groups\n", contextNames[i], total, len(contextLogGroups[i]))
	}

	// Step 3 & 4: For each unique SKI (potential parent key), find the optimal cert to include as parent.
	type row struct {
		ski     string
		parents [4]string
	}
	rows := make([]*row, 0, len(certsBySKI))
	skiCount := 0

	for ski, candidates := range certsBySKI {
		skiCount++
		if skiCount%100 == 0 || skiCount == len(certsBySKI) {
			fmt.Printf("\rProcessing SKI group %d/%d...", skiCount, len(certsBySKI))
		}

		r := &row{
			ski: strings.ToUpper(ski),
		}

		for ctxIdx, groups := range contextLogGroups {
			var bestScore int
			var bestChainLen int
			var bestNotAfter time.Time
			var bestCertHash [sha256.Size]byte
			hasResult := false

			for _, ci := range candidates {
				// For self-signed roots, the "chain" is just the root itself (length 1).
				// For intermediates, build chains upward to find accepted roots.
				var chains [][][]byte
				if isSelfSigned(ci) {
					chains = [][][]byte{{ci.raw}}
				} else {
					chains = buildChains(ci, certsBySKI)
				}

				for _, chain := range chains {
					// Check if the chain's root is in each accepted roots pool.
					rootHash := sha256.Sum256(chain[len(chain)-1])

					score := 0
					for _, g := range groups {
						if rootHashSets[g.rootsHash][rootHash] {
							score += g.count
						}
					}

					if score > 0 {
						switch {
						case !hasResult, score > bestScore:
						case score < bestScore:
							continue
						case len(chain) < bestChainLen:
						case len(chain) > bestChainLen:
							continue
						case ci.cert.NotAfter.After(bestNotAfter):
						case ci.cert.NotAfter.Before(bestNotAfter):
							continue
						case bytes.Compare(ci.sha256[:], bestCertHash[:]) < 0:
						default:
							continue
						}
						bestScore = score
						bestChainLen = len(chain)
						bestNotAfter = ci.cert.NotAfter
						bestCertHash = ci.sha256
						hasResult = true
					}
				}
			}

			if hasResult {
				r.parents[ctxIdx] = strings.ToUpper(hex.EncodeToString(bestCertHash[:]))
			}
		}

		// Only include rows that have at least one parent.
		hasAnyParent := false
		for _, p := range r.parents {
			if p != "" {
				hasAnyParent = true
				break
			}
		}
		if hasAnyParent {
			rows = append(rows, r)
		}
	}
	fmt.Println()

	// Sort rows by SKI.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].ski < rows[j].ski
	})

	// Write CSV output.
	f, err := os.Create("optimal_parents.csv")
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"Authority Key Identifier", "Parent (Usable TLS)", "Parent (Active TLS)", "Parent (Test TLS)", "Parent (Usable BIMI)"})
	for _, r := range rows {
		_ = w.Write([]string{r.ski, r.parents[0], r.parents[1], r.parents[2], r.parents[3]})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatalf("Failed to write CSV: %v", err)
	}

	fmt.Printf("Wrote %d rows to optimal_parents.csv\n", len(rows))
}
func loadCCADBCerts() []*certInfo {
	dataDir := filepath.Join(getCcadbDataDir(), "cmd", "ski_spki", "data")
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("Failed to read CCADB data directory %s: %v", dataDir, err)
	}

	seen := make(map[[sha256.Size]byte]bool)
	var certs []*certInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			log.Printf("Warning: could not read %s: %v", entry.Name(), err)
			continue
		}

		reader := csv.NewReader(strings.NewReader(string(data)))
		reader.FieldsPerRecord = 2
		reader.LazyQuotes = true
		reader.TrimLeadingSpace = true
		reader.ReuseRecord = true
		records, err := reader.ReadAll()
		if err != nil {
			log.Printf("Warning: could not parse CSV %s: %v", entry.Name(), err)
			continue
		}

		for _, record := range records[1:] {
			block, _ := pem.Decode([]byte(record[1]))
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			hash := sha256.Sum256(block.Bytes)
			if seen[hash] {
				continue
			}
			seen[hash] = true
			certs = append(certs, &certInfo{
				cert:   cert,
				raw:    block.Bytes,
				sha256: hash,
			})
		}
	}
	return certs
}

// buildChains returns the shortest chain from the given certificate to each
// reachable self-signed root, deduplicated by root hash. Uses BFS to guarantee
// shortest-first discovery, avoiding the combinatorial explosion of enumerating
// all possible paths through cross-certified intermediates.
// Returns nil for self-signed (root) certificates.
func buildChains(ci *certInfo, certsBySKI map[string][]*certInfo) [][][]byte {
	if isSelfSigned(ci) {
		return nil
	}

	// BFS state: each node is a certInfo with the path (as DER slices) that reached it.
	type bfsNode struct {
		ci   *certInfo
		path [][]byte // DER certs from ci (the starting cert) through to this node.
	}

	queue := []bfsNode{{ci: ci, path: [][]byte{ci.raw}}}
	visited := map[[sha256.Size]byte]bool{ci.sha256: true}
	seenRoots := map[[sha256.Size]byte]bool{} // Deduplicate by root cert hash.

	var chains [][][]byte

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for _, parent := range findParents(node.ci, certsBySKI) {
			if visited[parent.sha256] {
				continue
			}

			newPath := make([][]byte, len(node.path)+1)
			copy(newPath, node.path)
			newPath[len(node.path)] = parent.raw

			if isSelfSigned(parent) {
				rootHash := parent.sha256
				if !seenRoots[rootHash] {
					seenRoots[rootHash] = true
					chains = append(chains, newPath)
				}
				// Don't enqueue roots; they're terminal.
				continue
			}

			visited[parent.sha256] = true
			queue = append(queue, bfsNode{ci: parent, path: newPath})
		}
	}

	if len(chains) == 0 {
		// No root found; return a single-element chain.
		chains = [][][]byte{{ci.raw}}
	}

	return chains
}

func isSelfSigned(ci *certInfo) bool {
	if ci.cert.AuthorityKeyId != nil && ci.cert.SubjectKeyId != nil {
		return bytes.Equal(ci.cert.AuthorityKeyId, ci.cert.SubjectKeyId)
	}
	return bytes.Equal(ci.cert.RawIssuer, ci.cert.RawSubject)
}

func findParents(ci *certInfo, certsBySKI map[string][]*certInfo) []*certInfo {
	if len(ci.cert.AuthorityKeyId) == 0 {
		return nil
	}
	aki := hex.EncodeToString(ci.cert.AuthorityKeyId)
	var parents []*certInfo
	for _, c := range certsBySKI[aki] {
		if c.sha256 != ci.sha256 {
			parents = append(parents, c)
		}
	}
	return parents
}

// forEachLog calls fn for each log (including tiled logs) in the log list.
func forEachLog(ll *loglist3.LogList, fn func(logID [sha256.Size]byte)) {
	if ll == nil {
		return
	}
	for _, op := range ll.Operators {
		for _, l := range op.Logs {
			fn(sha256.Sum256(l.Key))
		}
		for _, tl := range op.TiledLogs {
			fn(sha256.Sum256(tl.Key))
		}
	}
}

// getCcadbDataDir locates the ccadb_data module directory in the Go module cache.
func getCcadbDataDir() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("Failed to read build info")
	}

	modCache := os.Getenv("GOMODCACHE")
	if modCache == "" {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			home, _ := os.UserHomeDir()
			gopath = filepath.Join(home, "go")
		}
		modCache = filepath.Join(gopath, "pkg", "mod")
	}

	for _, dep := range bi.Deps {
		if dep.Path == "github.com/crtsh/ccadb_data" {
			return filepath.Join(modCache, dep.Path+"@"+dep.Version)
		}
	}
	log.Fatal("github.com/crtsh/ccadb_data dependency not found in build info")
	return ""
}
