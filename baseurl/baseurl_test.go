package baseurl

import (
	"sync"
	"testing"
)

func TestNewAndGet(t *testing.T) {
	b := New("http://localhost:3000")
	if got := b.Get(); got != "http://localhost:3000" {
		t.Fatalf("Get() = %q, want %q", got, "http://localhost:3000")
	}
}

func TestSet(t *testing.T) {
	b := New("http://localhost:3000")
	b.Set("https://example.com")
	if got := b.Get(); got != "https://example.com" {
		t.Fatalf("after Set, Get() = %q, want %q", got, "https://example.com")
	}
}

func TestConcurrent(t *testing.T) {
	b := New("http://initial")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			b.Set("http://updated")
		}()
		go func() {
			defer wg.Done()
			_ = b.Get()
		}()
	}
	wg.Wait()
	// If we got here without a race detector failure, concurrent access is safe.
	got := b.Get()
	if got != "http://initial" && got != "http://updated" {
		t.Fatalf("unexpected value: %q", got)
	}
}
