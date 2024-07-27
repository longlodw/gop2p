package gop2p

import (
	"sync"
	"sync/atomic"
)

type mergeStream[T any] struct {
  count atomic.Int32
  buffer []T
  mutex  sync.Mutex
}

func newMergeStream[T any]() *mergeStream[T] {
  return &mergeStream[T]{
    count: atomic.Int32{},
    buffer: make([]T, 0),
    mutex: sync.Mutex{},
  }
}

func (ms *mergeStream[T]) add(values []T) []T {
  ms.count.Add(1)
  ms.mutex.Lock()
  defer ms.mutex.Unlock()
  ms.buffer = append(ms.buffer, values...)
  ms.count.Add(-1)
  if ms.count.Load() == 0 {
    buffer := ms.buffer
    ms.buffer = make([]T, 0, len(buffer))
    return buffer
  }
  return nil
}

