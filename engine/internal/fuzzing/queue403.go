package fuzzing

import (
	"container/heap"
	"sync"
)

type queued403 struct {
	entry    QueueEntry
	seq      int64
	index    int
}

type priority403Heap []*queued403

func (h priority403Heap) Len() int { return len(h) }
func (h priority403Heap) Less(i, j int) bool {
	if h[i].entry.Priority == h[j].entry.Priority {
		return h[i].seq < h[j].seq
	}
	return h[i].entry.Priority > h[j].entry.Priority
}
func (h priority403Heap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *priority403Heap) Push(x interface{}) {
	n := len(*h)
	item := x.(*queued403)
	item.index = n
	*h = append(*h, item)
}
func (h *priority403Heap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[:n-1]
	return item
}

type Queue403 struct {
	mu               sync.Mutex
	maxSize          int
	seen             map[string]struct{}
	heap             priority403Heap
	seq              int64
	totalEnqueued    int
	totalDeduplicated int
	totalProcessed   int
	totalEvicted     int
}

// lowestPriorityIndex returns the heap index of the entry with the smallest
// priority (ties broken by the largest seq, i.e. the most recently added).
// Returns -1 when the heap is empty.
func (q *Queue403) lowestPriorityIndex() int {
	if len(q.heap) == 0 {
		return -1
	}
	minIdx := 0
	for i := 1; i < len(q.heap); i++ {
		cur := q.heap[i].entry.Priority
		best := q.heap[minIdx].entry.Priority
		if cur < best || (cur == best && q.heap[i].seq > q.heap[minIdx].seq) {
			minIdx = i
		}
	}
	return minIdx
}

func NewQueue403(maxSize int) *Queue403 {
	if maxSize <= 0 {
		maxSize = 10000
	}
	q := &Queue403{
		maxSize: maxSize,
		seen:    make(map[string]struct{}),
	}
	heap.Init(&q.heap)
	return q
}

func (q *Queue403) Enqueue(url, method string) bool {
	key := method + " " + url
	q.mu.Lock()
	defer q.mu.Unlock()

	if _, ok := q.seen[key]; ok {
		q.totalDeduplicated++
		return false
	}
	if len(q.heap) >= q.maxSize {
		// Queue is full: only admit the new URL if it outranks the current
		// lowest-priority entry, evicting that entry. This prevents
		// high-value targets (e.g. /admin, /actuator) from being dropped just
		// because lower-priority paths arrived first.
		newPriority := Score403Priority(url, method)
		minIdx := q.lowestPriorityIndex()
		if minIdx < 0 || newPriority <= q.heap[minIdx].entry.Priority {
			q.totalDeduplicated++
			return false
		}
		evicted := heap.Remove(&q.heap, minIdx).(*queued403)
		delete(q.seen, dedupeKey(evicted.entry.Method, evicted.entry.URL))
		q.totalEvicted++
	}
	q.seen[key] = struct{}{}
	q.seq++
	entry := QueueEntry{
		URL: url, Method: method, Priority: Score403Priority(url, method),
	}
	heap.Push(&q.heap, &queued403{entry: entry, seq: q.seq})
	q.totalEnqueued++
	return true
}

func (q *Queue403) Dequeue() (QueueEntry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.heap.Len() == 0 {
		return QueueEntry{}, false
	}
	item := heap.Pop(&q.heap).(*queued403)
	q.totalProcessed++
	return item.entry, true
}

func (q *Queue403) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.heap.Len()
}

type Queue403Metrics struct {
	Size              int `json:"size"`
	TotalEnqueued     int `json:"total_enqueued"`
	TotalDeduplicated int `json:"total_deduplicated"`
	TotalProcessed    int `json:"total_processed"`
	TotalEvicted      int `json:"total_evicted"`
	MaxSize           int `json:"max_size"`
}

func (q *Queue403) Metrics() Queue403Metrics {
	q.mu.Lock()
	defer q.mu.Unlock()
	return Queue403Metrics{
		Size: q.heap.Len(), TotalEnqueued: q.totalEnqueued,
		TotalDeduplicated: q.totalDeduplicated, TotalProcessed: q.totalProcessed,
		TotalEvicted: q.totalEvicted,
		MaxSize:      q.maxSize,
	}
}

func dedupeKey(method, url string) string {
	return method + " " + url
}
