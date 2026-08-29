// Package pool provides a generic, type-safe object pool that allocates nothing
// on Get and Put once warm.
package pool

import "sync"

// Pool is a typed wrapper over sync.Pool. Storing a value type in sync.Pool
// directly boxes it into an interface on every Put (staticcheck SA6002), so the
// value travels in a pooled pointer instead: the secondary pool recycles the
// pointers themselves, and neither direction allocates once both pools are warm.
type Pool[T any] struct {
	items    sync.Pool
	pointers sync.Pool
	new      func() T
}

// New creates a pool that hands out values built by newItem.
func New[T any](newItem func() T) *Pool[T] {
	return &Pool[T]{new: newItem}
}

// Get returns a pooled value, or a newly built one when the pool is empty.
func (p *Pool[T]) Get() T {
	boxed, ok := p.items.Get().(*T)
	if !ok {
		return p.new()
	}

	value := *boxed
	var zero T
	*boxed = zero
	p.pointers.Put(boxed)
	return value
}

// Put stores value for reuse.
func (p *Pool[T]) Put(value T) {
	boxed, ok := p.pointers.Get().(*T)
	if !ok {
		boxed = new(T)
	}

	*boxed = value
	p.items.Put(boxed)
}
