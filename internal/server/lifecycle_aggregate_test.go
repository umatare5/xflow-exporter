package server

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// netflowV5Datagram builds one v5 record, whose port an enricher can name.
func netflowV5Datagram() []byte {
	payload := make([]byte, 24+48)
	binary.BigEndian.PutUint16(payload[0:2], 5)
	binary.BigEndian.PutUint16(payload[2:4], 1)
	binary.BigEndian.PutUint16(payload[24+34:24+36], 443)
	payload[24+38] = 6
	return payload
}

// netflowV8Datagram builds one AS aggregate, the method carrying no address.
func netflowV8Datagram() []byte {
	payload := make([]byte, 28+28)
	binary.BigEndian.PutUint16(payload[0:2], 8)
	binary.BigEndian.PutUint16(payload[2:4], 1)
	payload[22] = 1 // aggregation method
	payload[23] = 2 // aggregation export version
	return payload
}

// TestDecodeLoop_LeavesAnAggregateUnenriched pins the first of the three gates
// D1-a needs. An aggregate reaches no table a lookup fills, so enriching it
// spends the lookup and counts it as work the series never show.
func TestDecodeLoop_LeavesAnAggregateUnenriched(t *testing.T) {
	t.Parallel()

	filled := func(chain *enrich.Chain) uint64 {
		var total uint64
		for _, s := range chain.Snapshot() {
			total += s.Filled + s.Unknown + s.Skipped
		}
		return total
	}

	run := func(payload []byte) uint64 {
		recv := receiver.New(config.Receiver{MaxPacketSize: 128, QueueSize: 1})
		dec := decoder.New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          config.DefaultParserTemplateTTL,
		})
		chain, _, _, _, err := buildEnrichmentChain(config.Enrichment{Services: true})
		if err != nil {
			t.Fatalf("buildEnrichmentChain() error = %v, want nil", err)
		}

		in := make(chan receiver.Packet, 1)
		in <- receiver.Packet{
			Src:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 2055),
			Data: payload,
		}
		close(in)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			decodeLoop(recv, in, dec, chain, nil, nil)
		}()
		wg.Wait()
		return filled(chain)
	}

	if got := run(netflowV5Datagram()); got == 0 {
		t.Fatalf("lookups = %d on a per-flow record, want the chain to have run", got)
	}
	if got := run(netflowV8Datagram()); got != 0 {
		t.Errorf("lookups = %d on an aggregate, want none", got)
	}
}
