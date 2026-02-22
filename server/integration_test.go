package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/taw/zkettle/store"
)

func newIntegrationServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	viewerFS := fstest.MapFS{
		"viewer.html": &fstest.MapFile{Data: []byte("<html>viewer</html>")},
		"index.html":  &fstest.MapFile{Data: []byte("<html>landing</html>")},
		"create.html": &fstest.MapFile{Data: []byte("<html>create</html>")},
	}
	srv := New(context.Background(), Config{}, st, viewerFS)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func postSecret(t *testing.T, ts *httptest.Server, views, minutes int) (id, deleteToken string) {
	t.Helper()
	body := map[string]any{
		"encrypted": "dGVzdA",
		"iv":        "MTIzNDU2Nzg5MDEy",
		"views":     views,
		"minutes":   minutes,
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/api/secrets", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST: got %d, want 201. Body: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result["id"].(string), result["delete_token"].(string)
}

func getSecret(t *testing.T, ts *httptest.Server, id string) int {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/secrets/" + id)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// (1) create -> read -> verify consumed (404 on second read)
func TestIntegrationCreateReadConsumed(t *testing.T) {
	ts, _ := newIntegrationServer(t)

	id, _ := postSecret(t, ts, 1, 24)

	// First read succeeds
	if code := getSecret(t, ts, id); code != http.StatusOK {
		t.Fatalf("first read: got %d, want 200", code)
	}

	// Second read returns 404
	if code := getSecret(t, ts, id); code != http.StatusNotFound {
		t.Fatalf("second read: got %d, want 404", code)
	}
}

// (2) create with views=3 -> read 3 times -> verify 404
func TestIntegrationMultiViewExhaustion(t *testing.T) {
	ts, _ := newIntegrationServer(t)

	id, _ := postSecret(t, ts, 3, 24)

	for i := 0; i < 3; i++ {
		if code := getSecret(t, ts, id); code != http.StatusOK {
			t.Fatalf("read %d: got %d, want 200", i+1, code)
		}
	}

	if code := getSecret(t, ts, id); code != http.StatusNotFound {
		t.Fatalf("read after exhaustion: got %d, want 404", code)
	}
}

// (3) create -> delete -> verify 404
func TestIntegrationCreateDeleteVerify(t *testing.T) {
	ts, _ := newIntegrationServer(t)

	id, deleteToken := postSecret(t, ts, 5, 24)

	// Delete with correct token
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/secrets/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+deleteToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want 204", resp.StatusCode)
	}

	// Verify it's gone
	if code := getSecret(t, ts, id); code != http.StatusNotFound {
		t.Fatalf("GET after DELETE: got %d, want 404", code)
	}
}

// (4) create with 1s TTL -> wait -> verify status returns 410/404
func TestIntegrationTTLExpiry(t *testing.T) {
	ts, st := newIntegrationServer(t)

	// Create directly in store with 1s TTL (API hours minimum is 1)
	testID := "bb000000000000000000000000000001"
	st.Create(testID, []byte("enc"), []byte("123456789012"), 1, time.Now().Add(1*time.Second), "tok")

	// Status should be available immediately
	resp, err := http.Get(ts.URL + "/api/secrets/" + testID + "/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status before expiry: got %d, want 200", resp.StatusCode)
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Status should return 404 (expired)
	resp, err = http.Get(ts.URL + "/api/secrets/" + testID + "/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status after expiry: got %d, want 404", resp.StatusCode)
	}
}

// (5) POST without Content-Type -> 415
func TestIntegrationContentTypeEnforcement(t *testing.T) {
	ts, _ := newIntegrationServer(t)

	body := []byte(`{"encrypted":"dGVzdA","iv":"MTIzNDU2Nzg5MDEy","views":1,"minutes":1440}`)
	resp, err := http.Post(ts.URL+"/api/secrets", "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("POST text/plain: got %d, want 415", resp.StatusCode)
	}
}

// (6) GET with malformed ID -> 400
func TestIntegrationMalformedID(t *testing.T) {
	ts, _ := newIntegrationServer(t)

	resp, err := http.Get(ts.URL + "/api/secrets/not-a-valid-hex-id")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET malformed ID: got %d, want 400", resp.StatusCode)
	}
}

// (7) CORS headers with configured origins
func TestIntegrationCORSHeaders(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	viewerFS := fstest.MapFS{
		"viewer.html": &fstest.MapFile{Data: []byte("<html>viewer</html>")},
		"index.html":  &fstest.MapFile{Data: []byte("<html>landing</html>")},
		"create.html": &fstest.MapFile{Data: []byte("<html>create</html>")},
	}
	srv := New(context.Background(), Config{}, st, viewerFS)

	// Wrap with CORS middleware
	handler := CORSMiddleware([]string{"https://example.com"})(srv.Handler())
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	// Request with matching origin
	req, _ := http.NewRequest("GET", ts.URL+"/health", nil)
	req.Header.Set("Origin", "https://example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("CORS origin: got %q, want %q", got, "https://example.com")
	}

	// Preflight
	req, _ = http.NewRequest("OPTIONS", ts.URL+"/api/secrets", nil)
	req.Header.Set("Origin", "https://example.com")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("preflight missing Allow-Methods")
	}
}

