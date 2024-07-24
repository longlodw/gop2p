package gop2p

import (
	"sync"
	"sync/atomic"
)

type MergeStream[T any] struct {
  count atomic.Int32
  buffer []T
  mutex  sync.Mutex
}

func NewMergeStream[T any]() *MergeStream[T] {
  return &MergeStream[T]{
    count: atomic.Int32{},
    buffer: make([]T, 0),
    mutex: sync.Mutex{},
  }
}

func (ms *MergeStream[T]) Add(values []T) []T {
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

