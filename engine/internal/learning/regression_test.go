package learning_test

import (
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/storage"
	"sync"
	"testing"
)

func TestOutcomeCountsPersistWithoutDomainDoubleCounting(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/learning.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	store := learning.NewStore(db)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome := learning.OutcomeFalsePositive
			if i >= 20 {
				outcome = learning.OutcomeWorked
			}
			for _, endpoint := range []string{"", "https://example.com/a"} {
				if err := store.RecordOutcome("example.com", endpoint, "xss", outcome); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	loaded := learning.NewStore(db).Load("example.com", "https://example.com/a")
	if loaded.OutcomeCounts["xss"]["false_positive"] != 20 || loaded.OutcomeCounts["xss"]["worked"] != 10 {
		t.Fatalf("lost/duplicated outcomes: %+v", loaded.OutcomeCounts)
	}
	if got := loaded.FalsePositiveRate("xss"); got != 2.0/3.0 {
		t.Fatalf("rate %v", got)
	}
	if err := store.RecordOutcome("example.com", "https://example.com/a", "xss", learning.OutcomeInconclusive); err != nil {
		t.Fatal(err)
	}
	if got := store.Load("example.com", "https://example.com/a").FalsePositiveRate("xss"); got != 2.0/3.0 {
		t.Fatalf("inconclusive changed conclusive rate: %v", got)
	}
}
