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

func TestPool_PutThenGetReturnsTheValue(t *testing.T) {
	t.Parallel()

	p := New(func() []byte { return make([]byte, 4) })

	buf := p.Get()
	buf[0] = 0xAB
	p.Put(buf)

	got := p.Get()
	if got[0] != 0xAB {
		t.Errorf("Get() after Put() returned a fresh buffer, want the pooled one")
	}
}

//nolint:paralleltest // testing.AllocsPerRun panics inside a parallel test.
func TestPool_GetAllocatesNothingOnceWarm(t *testing.T) {
	p := New(func() []byte { return make([]byte, 1500) })

	// Warm both internal pools.
	p.Put(p.Get())

	allocs := testing.AllocsPerRun(100, func() {
		p.Put(p.Get())
	})
	if allocs != 0 {
		t.Errorf("Get/Put allocated %v times per run, want 0", allocs)
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
