package queue

import (
	"container/heap"
	"sync"
)

type Item struct {
	URL       string
	Method    string
	Priority  int
	Depth     int
	Body      []byte
	Headers   map[string]string
	Source    string
	Why       string
	ParentURL string
}

type priorityQueue []*Item

func (pq priorityQueue) Len() int { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool {
	if pq[i].Priority == pq[j].Priority {
		return pq[i].URL < pq[j].URL
	}
	return pq[i].Priority > pq[j].Priority
}
func (pq priorityQueue) Swap(i, j int)       { pq[i], pq[j] = pq[j], pq[i] }
func (pq *priorityQueue) Push(x interface{}) { *pq = append(*pq, x.(*Item)) }
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[:n-1]
	return item
}

type RequestQueue struct {
	mu   sync.Mutex
	pq   priorityQueue
	seen map[string]struct{}
}

func NewRequestQueue() *RequestQueue {
	q := &RequestQueue{
		pq:   make(priorityQueue, 0),
		seen: make(map[string]struct{}),
	}
	heap.Init(&q.pq)
	return q
}

func (q *RequestQueue) Enqueue(item Item) bool {
	key := item.Method + " " + item.URL
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.seen[key]; ok {
		return false
	}
	q.seen[key] = struct{}{}
	heap.Push(&q.pq, &item)
	return true
}

func (q *RequestQueue) Dequeue() (Item, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pq.Len() == 0 {
		return Item{}, false
	}
	item := heap.Pop(&q.pq).(*Item)
	return *item, true
}

func (q *RequestQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pq.Len()
}

func (q *RequestQueue) Snapshot() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, 0, q.pq.Len())
	for _, item := range q.pq {
		out = append(out, item.URL)
	}
	return out
}
