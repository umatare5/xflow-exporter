package server

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/umatare5/xflow-exporter/internal/collector"
)

// EntryLister reads the aggregation tables the listing reports.
type EntryLister interface {
	Aggregations() []string
	EntryScope() (topK int, minBytes uint64)
	Entries(name string) (collector.AggregationEntries, bool)
}

// entriesWriteTimeout bounds one listing's write. Without it a client that
// stops reading holds the single slot below until it disconnects, and one such
// connection is then all it takes to refuse every other listing. It is
// generous for the largest body the entry bound can produce.
const entriesWriteTimeout = 60 * time.Second

// entriesHandler lists what the aggregation tables hold, the entries the
// scrape-time cuts withhold included.
//
// One listing at a time. A table runs to --aggregation.max-entries where a
// scrape publishes Top-K, and no route here authenticates, so a second
// concurrent listing is all it takes to buy an OOM -- which on a push protocol
// costs the flows that arrive while the process is gone.
//
// A table is written as it is read rather than after all of them are, so the
// listing holds one table rather than eleven.
func entriesHandler(lister EntryLister) http.HandlerFunc {
	inFlight := make(chan struct{}, 1)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "only GET lists entries", http.StatusMethodNotAllowed)
			return
		}

		names, ok := askedFor(lister.Aggregations(), r)
		if !ok {
			http.Error(w, "aggregation must be one of "+strings.Join(lister.Aggregations(), ", "),
				http.StatusBadRequest)
			return
		}

		select {
		case inFlight <- struct{}{}:
			defer func() { <-inFlight }()
		default:
			http.Error(w, "another listing is in flight", http.StatusServiceUnavailable)
			return
		}

		// net/http clears the deadline once the handler returns, and a
		// recorder supports no deadline at all, so the error is dropped.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(entriesWriteTimeout))

		w.Header().Set("Content-Type", "application/json")
		writeEntries(w, lister, names)
	}
}

// askedFor resolves the aggregation parameter against the known names. An
// absent parameter asks for all of them; anything else has to name one, an
// empty or repeated value included.
//
// The query is parsed here rather than read through Query, which drops the
// pairs it cannot parse: a misencoded parameter would then arrive as an absent
// one and answer with every table.
func askedFor(known []string, r *http.Request) ([]string, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}

	asked := query["aggregation"]
	switch {
	case len(asked) == 0:
		return known, true
	case len(asked) == 1 && slices.Contains(known, asked[0]):
		return asked, true
	}
	return nil, false
}

// writeEntries streams the report. A table that is disabled carries no key,
// which is the absence its series have on /metrics.
func writeEntries(w http.ResponseWriter, lister EntryLister, names []string) {
	topK, minBytes := lister.EntryScope()

	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()

	_, _ = out.WriteString(`{"top_k":` + strconv.Itoa(topK) +
		`,"min_bytes":` + strconv.FormatUint(minBytes, 10) +
		`,"aggregations":{`)

	enc := json.NewEncoder(out)
	written := 0
	for _, name := range names {
		table, ok := lister.Entries(name)
		if !ok {
			continue
		}
		if written > 0 {
			_, _ = out.WriteString(`,`)
		}
		written++

		_, _ = out.WriteString(`"` + name + `":`)
		if err := enc.Encode(table); err != nil {
			// The status and the opening brace are already on the wire, so the
			// client reads a truncated body. Saying so here is what names it.
			slog.Error("Failed to write the entry listing", "aggregation", name, "error", err)
			return
		}
	}

	_, _ = out.WriteString(`}}`)
}
