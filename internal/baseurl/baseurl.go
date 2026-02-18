package baseurl

import "sync"

// BaseURL is a thread-safe mutable base URL.
// The tunnel URL is not known at startup — it arrives after cloudflared connects.
type BaseURL struct {
	mu  sync.RWMutex
	url string
}

func New(initial string) *BaseURL {
	return &BaseURL{url: initial}
}

func (b *BaseURL) Get() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.url
}

func (b *BaseURL) Set(url string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.url = url
}
