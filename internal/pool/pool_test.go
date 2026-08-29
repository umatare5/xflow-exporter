package pool

import (
	"sync"
	"testing"
)

func TestPool_GetBuildsWhenEmpty(t *testing.T) {
	t.Parallel()

	built := 0
	p := New(func() []byte {
		built++
		return make([]byte, 4)
	})

	buf := p.Get()
	if len(buf) != 4 {
		t.Errorf("Get() returned a buffer of length %d, want 4", len(buf))
	}
	if built != 1 {
		t.Errorf("constructor ran %d times, want 1", built)
	}
}

// TestPool_RecyclesValuesIntact pins that a value survives the round trip
// through the pointer box. Identity is deliberately not asserted: sync.Pool
// drops what it holds at every GC, so a Put followed by a Get is free to
// return a freshly built value, and a test demanding the pooled one back
// fails whenever the collector runs between the two.
func TestPool_RecyclesValuesIntact(t *testing.T) {
	t.Parallel()

	const (
		size = 4
		mark = 0xAB
		runs = 64
	)

	p := New(func() []byte { return make([]byte, size) })

	for range runs {
		buf := p.Get()
		for i := range buf {
			buf[i] = mark
		}
		p.Put(buf)
	}

	// Every value handed back is either one this test marked or a freshly
	// built one. A partially marked buffer would mean the box corrupted the
	// value on its way through the pool.
	recycled := 0
	for range runs {
		buf := p.Get()
		if len(buf) != size {
			t.Fatalf("Get() returned a buffer of length %d, want %d", len(buf), size)
		}

		marked, fresh := 0, 0
		for _, b := range buf {
			switch b {
			case mark:
				marked++
			case 0:
				fresh++
			}
		}
		if marked != size && fresh != size {
			t.Fatalf("Get() returned a partially marked buffer %v, want it intact", buf)
		}
		if marked == size {
			recycled++
		}
	}

	t.Logf("%d of %d values came back from the pool, the rest were rebuilt after a drop", recycled, runs)
}

//nolint:paralleltest // testing.AllocsPerRun panics inside a parallel test.
func TestPool_GetAllocatesNothingOnceWarm(t *testing.T) {
	p := New(func() []byte { return make([]byte, 1500) })

	// Warm both internal pools.
	p.Put(p.Get())

	// A GC during the measurement empties sync.Pool, and the Get that follows
	// rebuilds its value, so the average is not reliably zero. The bound
	// still separates the two outcomes it must tell apart: storing the value
	// rather than a pointer would allocate on every single Put, averaging one
	// or more, while an occasional rebuild after a drop averages near zero.
	const maxAllocsPerRun = 0.5

	allocs := testing.AllocsPerRun(100, func() {
		p.Put(p.Get())
	})
	if allocs >= maxAllocsPerRun {
		t.Errorf("Get/Put allocated %v times per run, want the steady state below %v",
			allocs, maxAllocsPerRun)
	}
}

func TestPool_ConcurrentUse(t *testing.T) {
	t.Parallel()

	p := New(func() []byte { return make([]byte, 8) })

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				p.Put(p.Get())
			}
		}()
	}
	wg.Wait()
}
