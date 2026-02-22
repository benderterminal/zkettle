package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds all resolved configuration values.
type Config struct {
	Port           int      `toml:"port"`
	Host           string   `toml:"host"`
	Data           string   `toml:"data"`
	BaseURL        string   `toml:"base_url"`
	CORSOrigins    []string `toml:"cors_origins"`
	TrustProxy     bool     `toml:"trust_proxy"`
	Tunnel         bool     `toml:"tunnel"`
	LogFormat      string   `toml:"log_format"` // "json" or "text" (default: "text")
	TLSCert        string   `toml:"tls_cert"`
	TLSKey         string   `toml:"tls_key"`
	AdminToken     string   `toml:"admin_token"`
	MaxSecretSize  int      `toml:"max_secret_size"` // bytes; 0 = default (512000)
	Metrics        bool     `toml:"metrics"`
}

// Defaults returns a Config with default values.
func Defaults() Config {
	return Config{
		Port: 3000,
		Host: "127.0.0.1",
		Data: "./data",
	}
}

// LoadFile attempts to load a TOML config file from standard locations.
// Search order: ./zkettle.toml, $HOME/.config/zkettle/zkettle.toml
// Returns the loaded config, the path that was loaded (empty if none found),
// a set of field names explicitly defined in the file, and any error.
// Returns an error only if a file exists but is malformed.
func LoadFile() (Config, string, map[string]bool, error) {
	paths := []string{"zkettle.toml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "zkettle", "zkettle.toml"))
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue // file not found, try next
		}
		var cfg Config
		md, err := toml.Decode(string(data), &cfg)
		if err != nil {
			return Config{}, p, nil, fmt.Errorf("parsing config file %s: %w", p, err)
		}
		fileSet := make(map[string]bool)
		for _, key := range []string{"port", "host", "data", "base_url", "cors_origins", "trust_proxy", "tunnel", "log_format", "tls_cert", "tls_key", "admin_token", "max_secret_size", "metrics"} {
			if md.IsDefined(key) {
				fileSet[key] = true
			}
		}
		return cfg, p, fileSet, nil
	}

	return Config{}, "", nil, nil
}

// LoadEnv reads ZKETTLE_* environment variables and returns a Config
// with only the fields that were set via env vars.
// Returns a Config and a set of field names that were explicitly set.
func LoadEnv() (Config, map[string]bool) {
	var cfg Config
	set := make(map[string]bool)

	if v := os.Getenv("ZKETTLE_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Port = port
			set["port"] = true
		}
	}
	if v := os.Getenv("ZKETTLE_HOST"); v != "" {
		cfg.Host = v
		set["host"] = true
	}
	if v := os.Getenv("ZKETTLE_DATA"); v != "" {
		cfg.Data = v
		set["data"] = true
	}
	if v := os.Getenv("ZKETTLE_BASE_URL"); v != "" {
		cfg.BaseURL = v
		set["base_url"] = true
	}
	if v := os.Getenv("ZKETTLE_CORS_ORIGINS"); v != "" {
		var origins []string
		for _, o := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
		cfg.CORSOrigins = origins
		set["cors_origins"] = true
	}
	if v := os.Getenv("ZKETTLE_TRUST_PROXY"); v != "" {
		cfg.TrustProxy = v == "true" || v == "1" || v == "yes"
		set["trust_proxy"] = true
	}
	if v := os.Getenv("ZKETTLE_TUNNEL"); v != "" {
		cfg.Tunnel = v == "true" || v == "1" || v == "yes"
		set["tunnel"] = true
	}
	if v := os.Getenv("ZKETTLE_LOG_FORMAT"); v != "" {
		cfg.LogFormat = v
		set["log_format"] = true
	}
	if v := os.Getenv("ZKETTLE_TLS_CERT"); v != "" {
		cfg.TLSCert = v
		set["tls_cert"] = true
	}
	if v := os.Getenv("ZKETTLE_TLS_KEY"); v != "" {
		cfg.TLSKey = v
		set["tls_key"] = true
	}
	if v := os.Getenv("ZKETTLE_ADMIN_TOKEN"); v != "" {
		cfg.AdminToken = v
		set["admin_token"] = true
	}
	if v := os.Getenv("ZKETTLE_MAX_SECRET_SIZE"); v != "" {
		if size, err := strconv.Atoi(v); err == nil {
			cfg.MaxSecretSize = size
			set["max_secret_size"] = true
		}
	}
	if v := os.Getenv("ZKETTLE_METRICS"); v != "" {
		cfg.Metrics = v == "true" || v == "1" || v == "yes"
		set["metrics"] = true
	}

	return cfg, set
}

// Validate checks that Config fields contain valid values.
// Returns an error if any field is invalid.
func (c Config) Validate() error {
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d: must be 0-65535", c.Port)
	}
	if c.Host != "" && c.Host != "localhost" {
		if net.ParseIP(c.Host) == nil {
			return fmt.Errorf("invalid host %q: must be a valid IP address or \"localhost\"", c.Host)
		}
	}
	switch c.LogFormat {
	case "", "json", "text":
		// valid
	default:
		return fmt.Errorf("invalid log_format %q: must be \"json\", \"text\", or empty", c.LogFormat)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must both be set or both be empty")
	}
	if c.TLSCert != "" {
		if _, err := os.Stat(c.TLSCert); err != nil {
			return fmt.Errorf("tls-cert file %q: %w", c.TLSCert, err)
		}
		if _, err := os.Stat(c.TLSKey); err != nil {
			return fmt.Errorf("tls-key file %q: %w", c.TLSKey, err)
		}
	}
	if c.MaxSecretSize < 0 {
		return fmt.Errorf("invalid max-secret-size %d: must be non-negative", c.MaxSecretSize)
	}
	if c.AdminToken != "" && len(c.AdminToken) < 16 {
		return fmt.Errorf("admin-token must be at least 16 characters")
	}
	return nil
}

// mergeLayer applies fields from src to dst for each key present in set.
// All keys use underscore format (e.g. "base_url", "trust_proxy").
func mergeLayer(dst *Config, src Config, set map[string]bool) {
	if set["port"] {
		dst.Port = src.Port
	}
	if set["host"] {
		dst.Host = src.Host
	}
	if set["data"] {
		dst.Data = src.Data
	}
	if set["base_url"] {
		dst.BaseURL = src.BaseURL
	}
	if set["cors_origins"] {
		dst.CORSOrigins = src.CORSOrigins
	}
	if set["trust_proxy"] {
		dst.TrustProxy = src.TrustProxy
	}
	if set["tunnel"] {
		dst.Tunnel = src.Tunnel
	}
	if set["log_format"] {
		dst.LogFormat = src.LogFormat
	}
	if set["tls_cert"] {
		dst.TLSCert = src.TLSCert
	}
	if set["tls_key"] {
		dst.TLSKey = src.TLSKey
	}
	if set["admin_token"] {
		dst.AdminToken = src.AdminToken
	}
	if set["max_secret_size"] {
		dst.MaxSecretSize = src.MaxSecretSize
	}
	if set["metrics"] {
		dst.Metrics = src.Metrics
	}
}

// Merge combines defaults, file config, env config, and flag overrides.
// Precedence: flags > env > file > defaults.
// All set maps use underscore-format keys (e.g. "base_url", "trust_proxy").
func Merge(defaults, file Config, fileSet map[string]bool, env Config, envSet map[string]bool, flags Config, flagSet map[string]bool) Config {
	result := defaults
	mergeLayer(&result, file, fileSet)
	mergeLayer(&result, env, envSet)
	mergeLayer(&result, flags, flagSet)
	return result
}

// ResolveAll loads config from file and env, merges with flags and defaults,
// validates, and checks mutual exclusivity constraints. Returns the resolved
// config and the config file path (empty if none found).
func ResolveAll(flagCfg Config, flagSet map[string]bool) (Config, string, error) {
	defaults := Defaults()
	fileCfg, filePath, fileSet, err := LoadFile()
	if err != nil {
		return Config{}, "", err
	}
	envCfg, envSet := LoadEnv()
	resolved := Merge(defaults, fileCfg, fileSet, envCfg, envSet, flagCfg, flagSet)

	if err := resolved.Validate(); err != nil {
		return Config{}, "", err
	}

	if resolved.Tunnel && resolved.BaseURL != "" {
		return Config{}, "", fmt.Errorf("--tunnel and --base-url are mutually exclusive")
	}
	if resolved.Tunnel && resolved.TLSCert != "" {
		return Config{}, "", fmt.Errorf("--tunnel and --tls-cert/--tls-key are mutually exclusive")
	}

	return resolved, filePath, nil
}
