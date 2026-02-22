package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.Port != 3000 {
		t.Fatalf("default port: got %d, want 3000", d.Port)
	}
	if d.Host != "127.0.0.1" {
		t.Fatalf("default host: got %q, want 127.0.0.1", d.Host)
	}
	if d.Data != "./data" {
		t.Fatalf("default data: got %q, want ./data", d.Data)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	// Run in a temp dir with no config file
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	cfg, path, fileSet, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("expected no file found, got path: %s", path)
	}
	if fileSet != nil {
		t.Fatalf("expected nil fileSet when no file found, got: %v", fileSet)
	}
	if cfg.Port != 0 {
		t.Fatalf("expected zero config from no file, got port: %d", cfg.Port)
	}
}

func TestLoadFileValid(t *testing.T) {
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	tomlContent := `
port = 4000
host = "0.0.0.0"
data = "/tmp/zkettle"
base_url = "https://example.com"
cors_origins = ["https://foo.com", "https://bar.com"]
trust_proxy = true
`
	os.WriteFile("zkettle.toml", []byte(tomlContent), 0o644)

	cfg, path, fileSet, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if path != "zkettle.toml" {
		t.Fatalf("expected zkettle.toml, got: %s", path)
	}
	if cfg.Port != 4000 {
		t.Fatalf("port: got %d, want 4000", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Fatalf("host: got %q, want 0.0.0.0", cfg.Host)
	}
	if cfg.Data != "/tmp/zkettle" {
		t.Fatalf("data: got %q, want /tmp/zkettle", cfg.Data)
	}
	if cfg.BaseURL != "https://example.com" {
		t.Fatalf("base_url: got %q, want https://example.com", cfg.BaseURL)
	}
	if len(cfg.CORSOrigins) != 2 {
		t.Fatalf("cors_origins: got %d, want 2", len(cfg.CORSOrigins))
	}
	if !cfg.TrustProxy {
		t.Fatal("trust_proxy: expected true")
	}
	// Verify fileSet tracks which keys were defined
	for _, key := range []string{"port", "host", "data", "base_url", "cors_origins", "trust_proxy"} {
		if !fileSet[key] {
			t.Fatalf("fileSet missing key %q", key)
		}
	}
	// tunnel and log_format were not in the file
	if fileSet["tunnel"] {
		t.Fatal("fileSet should not contain 'tunnel'")
	}
	if fileSet["log_format"] {
		t.Fatal("fileSet should not contain 'log_format'")
	}
}

func TestLoadFileMalformed(t *testing.T) {
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	os.WriteFile("zkettle.toml", []byte("this is not valid [[[toml"), 0o644)

	_, _, _, err := LoadFile()
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

func TestLoadFileHomeConfig(t *testing.T) {
	// Test that $HOME/.config/zkettle/zkettle.toml is found as fallback
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp) // No local zkettle.toml here
	defer os.Chdir(origDir)

	// Create a config in a temp "home" config dir
	homeConfig := filepath.Join(tmp, ".config", "zkettle")
	os.MkdirAll(homeConfig, 0o755)
	os.WriteFile(filepath.Join(homeConfig, "zkettle.toml"), []byte("port = 5000\n"), 0o644)

	// Override HOME for this test
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	cfg, path, _, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("expected to find home config file")
	}
	if cfg.Port != 5000 {
		t.Fatalf("port: got %d, want 5000", cfg.Port)
	}
}

func TestLoadEnv(t *testing.T) {
	// Set env vars
	os.Setenv("ZKETTLE_PORT", "4000")
	os.Setenv("ZKETTLE_HOST", "0.0.0.0")
	os.Setenv("ZKETTLE_DATA", "/tmp/data")
	os.Setenv("ZKETTLE_TRUST_PROXY", "true")
	os.Setenv("ZKETTLE_CORS_ORIGINS", "https://a.com, https://b.com")
	defer func() {
		os.Unsetenv("ZKETTLE_PORT")
		os.Unsetenv("ZKETTLE_HOST")
		os.Unsetenv("ZKETTLE_DATA")
		os.Unsetenv("ZKETTLE_TRUST_PROXY")
		os.Unsetenv("ZKETTLE_CORS_ORIGINS")
	}()

	cfg, set := LoadEnv()
	if !set["port"] || cfg.Port != 4000 {
		t.Fatalf("port: got %d, set=%v", cfg.Port, set["port"])
	}
	if !set["host"] || cfg.Host != "0.0.0.0" {
		t.Fatalf("host: got %q, set=%v", cfg.Host, set["host"])
	}
	if !set["data"] || cfg.Data != "/tmp/data" {
		t.Fatalf("data: got %q, set=%v", cfg.Data, set["data"])
	}
	if !set["trust_proxy"] || !cfg.TrustProxy {
		t.Fatal("trust_proxy not set")
	}
	if !set["cors_origins"] || len(cfg.CORSOrigins) != 2 {
		t.Fatalf("cors_origins: got %v, set=%v", cfg.CORSOrigins, set["cors_origins"])
	}
}

func TestMergePrecedence(t *testing.T) {
	defaults := Defaults()
	file := Config{Port: 4000, Host: "0.0.0.0"}
	fileSet := map[string]bool{"port": true, "host": true}
	env := Config{Port: 5000}
	envSet := map[string]bool{"port": true}
	flags := Config{Port: 6000}
	flagSet := map[string]bool{"port": true}

	result := Merge(defaults, file, fileSet, env, envSet, flags, flagSet)

	// Flag wins over env over file over default
	if result.Port != 6000 {
		t.Fatalf("port: got %d, want 6000 (flag)", result.Port)
	}
	// File wins over default (no env or flag override)
	if result.Host != "0.0.0.0" {
		t.Fatalf("host: got %q, want 0.0.0.0 (file)", result.Host)
	}
	// Default when nothing else set
	if result.Data != "./data" {
		t.Fatalf("data: got %q, want ./data (default)", result.Data)
	}
}

func TestMergeEnvOverridesFile(t *testing.T) {
	defaults := Defaults()
	file := Config{Port: 4000, Host: "0.0.0.0"}
	fileSet := map[string]bool{"port": true, "host": true}
	env := Config{Port: 5000}
	envSet := map[string]bool{"port": true}
	flags := Config{}
	flagSet := map[string]bool{}

	result := Merge(defaults, file, fileSet, env, envSet, flags, flagSet)

	if result.Port != 5000 {
		t.Fatalf("port: got %d, want 5000 (env overrides file)", result.Port)
	}
	if result.Host != "0.0.0.0" {
		t.Fatalf("host: got %q, want 0.0.0.0 (file, no env override)", result.Host)
	}
}

func TestMergeNoFile(t *testing.T) {
	defaults := Defaults()
	file := Config{}
	env := Config{}
	envSet := map[string]bool{}
	flags := Config{}
	flagSet := map[string]bool{}

	// nil fileSet simulates no file found
	result := Merge(defaults, file, nil, env, envSet, flags, flagSet)

	if result.Port != 3000 {
		t.Fatalf("port: got %d, want 3000 (default)", result.Port)
	}
}

func TestLoadEnvLogFormat(t *testing.T) {
	os.Setenv("ZKETTLE_LOG_FORMAT", "json")
	defer os.Unsetenv("ZKETTLE_LOG_FORMAT")

	cfg, set := LoadEnv()
	if !set["log_format"] {
		t.Fatal("expected log_format to be set")
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("log_format: got %q, want %q", cfg.LogFormat, "json")
	}
}

func TestMergeLogFormat(t *testing.T) {
	defaults := Defaults()
	file := Config{LogFormat: "json"}
	fileSet := map[string]bool{"log_format": true}
	env := Config{}
	envSet := map[string]bool{}
	flags := Config{}
	flagSet := map[string]bool{}

	result := Merge(defaults, file, fileSet, env, envSet, flags, flagSet)
	if result.LogFormat != "json" {
		t.Fatalf("log_format: got %q, want %q (from file)", result.LogFormat, "json")
	}

	// Env overrides file
	env.LogFormat = "text"
	envSet["log_format"] = true
	result = Merge(defaults, file, fileSet, env, envSet, flags, flagSet)
	if result.LogFormat != "text" {
		t.Fatalf("log_format: got %q, want %q (env overrides file)", result.LogFormat, "text")
	}
}

func TestMergeUnknownKeysIgnored(t *testing.T) {
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	// Unknown key "foo" should not cause an error
	os.WriteFile("zkettle.toml", []byte("port = 4000\nfoo = \"bar\"\n"), 0o644)

	_, _, _, err := LoadFile()
	if err != nil {
		t.Fatalf("unknown keys should be ignored, got error: %v", err)
	}
}

func TestMergeFileBooleanOverride(t *testing.T) {
	// Verify that a file with trust_proxy = false can override a true default,
	// and that tunnel = true correctly sets Tunnel.
	defaults := Defaults()
	defaults.TrustProxy = true // hypothetical: default is true

	file := Config{TrustProxy: false, Tunnel: true}
	fileSet := map[string]bool{"trust_proxy": true, "tunnel": true}
	env := Config{}
	envSet := map[string]bool{}
	flags := Config{}
	flagSet := map[string]bool{}

	result := Merge(defaults, file, fileSet, env, envSet, flags, flagSet)

	if result.TrustProxy != false {
		t.Fatalf("trust_proxy: got %v, want false (file overrides true default)", result.TrustProxy)
	}
	if result.Tunnel != true {
		t.Fatalf("tunnel: got %v, want true (file sets tunnel)", result.Tunnel)
	}
}

func TestMergeFileBooleanNotInFileSet(t *testing.T) {
	// If trust_proxy is not in fileSet, the default should be preserved
	// even if the file Config struct has the zero value.
	defaults := Defaults()
	defaults.TrustProxy = true // hypothetical: default is true

	file := Config{} // trust_proxy not set in file
	fileSet := map[string]bool{}
	env := Config{}
	envSet := map[string]bool{}
	flags := Config{}
	flagSet := map[string]bool{}

	result := Merge(defaults, file, fileSet, env, envSet, flags, flagSet)

	if result.TrustProxy != true {
		t.Fatalf("trust_proxy: got %v, want true (default preserved when not in fileSet)", result.TrustProxy)
	}
}

func TestLoadFileTracksFileSet(t *testing.T) {
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(origDir)

	// File explicitly sets trust_proxy to false and tunnel to true
	tomlContent := "trust_proxy = false\ntunnel = true\n"
	os.WriteFile("zkettle.toml", []byte(tomlContent), 0o644)

	cfg, _, fileSet, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if !fileSet["trust_proxy"] {
		t.Fatal("fileSet should contain 'trust_proxy' even when value is false")
	}
	if !fileSet["tunnel"] {
		t.Fatal("fileSet should contain 'tunnel'")
	}
	if cfg.TrustProxy != false {
		t.Fatal("trust_proxy: expected false")
	}
	if cfg.Tunnel != true {
		t.Fatal("tunnel: expected true")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid defaults", Defaults(), false},
		{"valid json log", Config{Port: 3000, LogFormat: "json"}, false},
		{"valid text log", Config{Port: 3000, LogFormat: "text"}, false},
		{"valid empty log", Config{Port: 3000, LogFormat: ""}, false},
		{"invalid log format", Config{Port: 3000, LogFormat: "xml"}, true},
		{"negative port", Config{Port: -1}, true},
		{"port too high", Config{Port: 65536}, true},
		{"max valid port", Config{Port: 65535}, false},
		{"zero port", Config{Port: 0}, false},
		{"valid host 0.0.0.0", Config{Host: "0.0.0.0"}, false},
		{"valid host 127.0.0.1", Config{Host: "127.0.0.1"}, false},
		{"valid host localhost", Config{Host: "localhost"}, false},
		{"valid host empty", Config{Host: ""}, false},
		{"valid host ipv6 loopback", Config{Host: "::1"}, false},
		{"invalid host not-an-ip", Config{Host: "not-an-ip"}, true},
		{"invalid host example.com", Config{Host: "example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
