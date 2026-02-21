package store

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGet(t *testing.T) {
	s := newTestStore(t)
	encrypted := []byte("encrypted-data")
	iv := []byte("123456789012")
	exp := time.Now().Add(1 * time.Hour)

	if err := s.Create("test-1", encrypted, iv, 1, exp, "tok"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	gotEnc, gotIV, err := s.Get("test-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(gotEnc) != string(encrypted) {
		t.Fatalf("encrypted mismatch: got %q, want %q", gotEnc, encrypted)
	}
	if string(gotIV) != string(iv) {
		t.Fatalf("iv mismatch: got %q, want %q", gotIV, iv)
	}
}

func TestSingleViewSecondGetFails(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("sv-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get("sv-1"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	_, _, err := s.Get("sv-1")
	if err != ErrNotFound {
		t.Fatalf("second Get: got %v, want ErrNotFound", err)
	}
}

func TestExpiredSecretReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	// Already expired
	if err := s.Create("exp-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(-1*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Get("exp-1")
	if err != ErrNotFound {
		t.Fatalf("expired Get: got %v, want ErrNotFound", err)
	}
}

func TestCleanupRemovesExpiredRows(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("clean-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(-1*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("clean-2", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}
	n, err := s.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if n != 1 {
		t.Fatalf("Cleanup removed %d rows, want 1", n)
	}
}

func TestListReturnsMetadata(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(1 * time.Hour)
	if err := s.Create("list-1", []byte("data1"), []byte("123456789012"), 3, exp, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("list-2", []byte("data2"), []byte("123456789012"), 1, exp, "tok"); err != nil {
		t.Fatal(err)
	}
	metas, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("List returned %d items, want 2", len(metas))
	}
	// Verify no encrypted content in metadata
	for _, m := range metas {
		if m.ID == "" {
			t.Fatal("empty ID in metadata")
		}
		if m.ViewsLeft <= 0 {
			t.Fatalf("unexpected views_left: %d", m.ViewsLeft)
		}
	}
}

func TestConcurrentGetSingleView(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("conc-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	successes := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.Get("conc-1")
			if err == nil {
				successes <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(successes)

	count := 0
	for range successes {
		count++
	}
	if count != 1 {
		t.Fatalf("concurrent Get: %d successes, want exactly 1", count)
	}
}

func TestDeleteSecret(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("del-1", []byte("data"), []byte("123456789012"), 5, time.Now().Add(1*time.Hour), "del-tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("del-1", "del-tok"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, _, err := s.Get("del-1")
	if err != ErrNotFound {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

func TestMultiViewSecret(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("mv-1", []byte("data"), []byte("123456789012"), 3, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := s.Get("mv-1"); err != nil {
			t.Fatalf("Get %d: %v", i+1, err)
		}
	}
	_, _, err := s.Get("mv-1")
	if err != ErrNotFound {
		t.Fatalf("Get after views exhausted: got %v, want ErrNotFound", err)
	}
}

func TestStatusAvailable(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("stat-1", []byte("data"), []byte("123456789012"), 3, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Status("stat-1"); err != nil {
		t.Fatalf("Status available: got %v, want nil", err)
	}
}

func TestStatusNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.Status("nonexistent")
	if err != ErrNotFound {
		t.Fatalf("Status not found: got %v, want ErrNotFound", err)
	}
}

func TestStatusExpired(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("stat-exp", []byte("data"), []byte("123456789012"), 3, time.Now().Add(-1*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	err := s.Status("stat-exp")
	if err != ErrExpired {
		t.Fatalf("Status expired: got %v, want ErrExpired", err)
	}
}

func TestCleanupMixedExpiry(t *testing.T) {
	s := newTestStore(t)
	iv := []byte("123456789012")
	expired := 0
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("mix-%04d", i)
		var exp time.Time
		if i%3 == 0 {
			exp = time.Now().Add(-1 * time.Second) // expired
			expired++
		} else {
			exp = time.Now().Add(1 * time.Hour) // active
		}
		if err := s.Create(id, []byte("data"), iv, 1, exp, "tok"); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	n, err := s.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if n != expired {
		t.Fatalf("Cleanup removed %d, want %d", n, expired)
	}
	// Verify active secrets still accessible
	for i := 0; i < 1000; i++ {
		if i%3 == 0 {
			continue
		}
		id := fmt.Sprintf("mix-%04d", i)
		if err := s.Status(id); err != nil {
			t.Fatalf("Status %s after cleanup: %v", id, err)
		}
	}
}

func TestExpiryTimerDeletesSecret(t *testing.T) {
	s := newTestStore(t)
	iv := []byte("123456789012")
	if err := s.Create("timer-1", []byte("data"), iv, 1, time.Now().Add(1*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	// Verify it exists
	if err := s.Status("timer-1"); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	// Wait for expiry + cleanup
	time.Sleep(2 * time.Second)
	// Row should be deleted from DB, not just inaccessible
	err := s.Status("timer-1")
	if err != ErrNotFound {
		t.Fatalf("after expiry timer: got %v, want ErrNotFound (row should be deleted)", err)
	}
}

func TestExpiryTimerDeletesAtExactTimes(t *testing.T) {
	s := newTestStore(t)
	iv := []byte("123456789012")
	// First secret expires in 1s
	if err := s.Create("exact-1", []byte("data"), iv, 1, time.Now().Add(1*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	// Second secret expires in 3s
	if err := s.Create("exact-2", []byte("data"), iv, 1, time.Now().Add(3*time.Second), "tok"); err != nil {
		t.Fatal(err)
	}
	// After 2s: first should be deleted, second still available
	time.Sleep(2 * time.Second)
	if err := s.Status("exact-1"); err != ErrNotFound {
		t.Fatalf("exact-1 after 2s: got %v, want ErrNotFound", err)
	}
	if err := s.Status("exact-2"); err != nil {
		t.Fatalf("exact-2 after 2s: got %v, want nil (still active)", err)
	}
	// After another 2s: second should also be deleted
	time.Sleep(2 * time.Second)
	if err := s.Status("exact-2"); err != ErrNotFound {
		t.Fatalf("exact-2 after 4s: got %v, want ErrNotFound", err)
	}
}

func TestPingSuccess(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping on live DB: %v", err)
	}
}

func TestPingAfterClose(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Ping(); err == nil {
		t.Fatal("Ping after Close: expected error, got nil")
	}
}

func TestStatusConsumed(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("stat-con", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok"); err != nil {
		t.Fatal(err)
	}
	// Consume the single view
	if _, _, err := s.Get("stat-con"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Row is deleted after views exhausted, so Status returns ErrNotFound
	err := s.Status("stat-con")
	if err != ErrNotFound {
		t.Fatalf("Status consumed: got %v, want ErrNotFound", err)
	}
}
