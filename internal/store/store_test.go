package store

import (
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

	if err := s.Create("test-1", encrypted, iv, 1, exp); err != nil {
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
	if err := s.Create("sv-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour)); err != nil {
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
	if err := s.Create("exp-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(-1*time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Get("exp-1")
	if err != ErrNotFound {
		t.Fatalf("expired Get: got %v, want ErrNotFound", err)
	}
}

func TestCleanupRemovesExpiredRows(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("clean-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(-1*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("clean-2", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour)); err != nil {
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
	if err := s.Create("list-1", []byte("data1"), []byte("123456789012"), 3, exp); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("list-2", []byte("data2"), []byte("123456789012"), 1, exp); err != nil {
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
	if err := s.Create("conc-1", []byte("data"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour)); err != nil {
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
	if err := s.Create("del-1", []byte("data"), []byte("123456789012"), 5, time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("del-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, _, err := s.Get("del-1")
	if err != ErrNotFound {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

func TestMultiViewSecret(t *testing.T) {
	s := newTestStore(t)
	if err := s.Create("mv-1", []byte("data"), []byte("123456789012"), 3, time.Now().Add(1*time.Hour)); err != nil {
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
