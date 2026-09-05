package server

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/umatare5/xflow-exporter/internal/config"
	"github.com/umatare5/xflow-exporter/internal/decoder"
	"github.com/umatare5/xflow-exporter/internal/enrich"
	"github.com/umatare5/xflow-exporter/internal/receiver"
)

// twoAddrsOnDifferentShards finds a pair the hash separates, so the test reads
// what the dispatcher does rather than what one seed happened to produce.
func twoAddrsOnDifferentShards(t *testing.T, workers int) (a, b netip.Addr) {
	t.Helper()

	a = netip.AddrFrom4([4]byte{10, 0, 0, 1})
	for i := 2; i < 256; i++ {
		b = netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		if shardOf(a, workers) != shardOf(b, workers) {
			return a, b
		}
	}
	t.Fatalf("no address in 10.0.0.0/24 lands on a shard other than %d", shardOf(a, workers))
	return a, b
}

// datagram returns a pooled-size buffer carrying payload, which is what the
// read loop hands the queue and what Release puts back.
func datagram(payload []byte) []byte {
	buf := make([]byte, 64)
	return buf[:copy(buf, payload)]
}

// v9Header is the smallest datagram the v9 decoder tracks a sequence from: it
// reads the header, then finds no flowset to walk.
func v9Header(sequence uint32) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 9)
	binary.BigEndian.PutUint32(payload[12:16], sequence)
	binary.BigEndian.PutUint32(payload[16:20], 1)
	return payload
}

// TestShardPackets_OneExporterOneWorkerInOrder pins the guarantee the sequence
// counters rest on: every datagram of one device reaches one worker, and it
// reaches it in the order the queue held it.
func TestShardPackets_OneExporterOneWorkerInOrder(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const workers, each = 4, 500

		first, second := twoAddrsOnDifferentShards(t, workers)
		in := make(chan receiver.Packet)

		var wg sync.WaitGroup
		shards := shardPackets(&wg, in, workers)

		// One collector per shard, so a full shard cannot stall the
		// dispatcher and take every sender down with it.
		seen := make([][]receiver.Packet, workers)
		var collectors sync.WaitGroup
		for i, shard := range shards {
			collectors.Add(1)
			go func() {
				defer collectors.Done()
				for pkt := range shard {
					seen[i] = append(seen[i], pkt)
				}
			}()
		}

		for i := range each {
			seq := make([]byte, 4)
			binary.BigEndian.PutUint32(seq, uint32(i))
			in <- receiver.Packet{Src: netip.AddrPortFrom(first, 2055), Data: datagram(seq)}
			in <- receiver.Packet{Src: netip.AddrPortFrom(second, 2055), Data: datagram(seq)}
		}
		close(in)
		wg.Wait()
		collectors.Wait()

		total := 0
		for i, packets := range seen {
			total += len(packets)
			if len(packets) == 0 {
				continue
			}

			src := packets[0].Src.Addr()
			for j, pkt := range packets {
				if pkt.Src.Addr() != src {
					t.Fatalf("shard %d holds %v and %v, want one exporter", i, src, pkt.Src.Addr())
				}
				if got := binary.BigEndian.Uint32(pkt.Data); got != uint32(j) {
					t.Fatalf("shard %d position %d carries %d, want the arrival order", i, j, got)
				}
			}
		}
		if total != 2*each {
			t.Errorf("shards hold %d datagrams, want %d", total, 2*each)
		}
	})
}

// TestShardOf_SpreadsOneHostPerSubnet pins that the hash reads the whole
// address. One host per subnet differs only in the middle octets, which a hash
// of the low word alone would fold onto one worker.
func TestShardOf_SpreadsOneHostPerSubnet(t *testing.T) {
	t.Parallel()

	const workers = 8

	used := make([]bool, workers)
	for i := range 256 {
		used[shardOf(netip.AddrFrom4([4]byte{10, 1, byte(i), 1}), workers)] = true
	}
	// The default listener binds dual-stack, so a native IPv6 device reaches
	// the same hash with a 16-byte address, which As4 would panic on.
	used[shardOf(netip.MustParseAddr("2001:db8::1"), workers)] = true
	for shard, ok := range used {
		if !ok {
			t.Errorf("shard %d took none of 256 one-host subnets", shard)
		}
	}
}

// TestDecodeLoop_KeepsSequencePerExporter is the regression this change exists
// for: the same datagrams through one shared queue had the workers racing each
// other, and the sequence counters read that race as export loss.
func TestDecodeLoop_KeepsSequencePerExporter(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const workers, sources, each = 4, 4, 2000

		recv := receiver.New(config.Receiver{MaxPacketSize: 64, QueueSize: 1})
		dec := decoder.New(config.Parser{
			MaxFieldsPerTemplate: config.DefaultParserMaxFieldsPerTemplate,
			TemplateTTL:          config.DefaultParserTemplateTTL,
		})
		chain := enrich.NewChain()

		in := make(chan receiver.Packet)
		var wg sync.WaitGroup
		for _, shard := range shardPackets(&wg, in, workers) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				decodeLoop(recv, shard, dec, chain, nil, nil)
			}()
		}

		for i := range each {
			for s := range sources {
				in <- receiver.Packet{
					Src:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(s + 1)}), 2055),
					Data: datagram(v9Header(uint32(i))),
				}
			}
		}
		close(in)
		wg.Wait()

		domains := dec.Domains()
		if len(domains) != sources {
			t.Fatalf("Domains() = %d, want one per source", len(domains))
		}
		for _, d := range domains {
			if d.SequenceMissed != 0 {
				t.Errorf("exporter %v missed %d, want 0 from an unbroken sequence",
					d.Exporter, d.SequenceMissed)
			}
		}
	})
}
