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
	Port        int      `toml:"port"`
	Host        string   `toml:"host"`
	Data        string   `toml:"data"`
	BaseURL     string   `toml:"base_url"`
	CORSOrigins []string `toml:"cors_origins"`
	TrustProxy  bool     `toml:"trust_proxy"`
	Tunnel      bool     `toml:"tunnel"`
	LogFormat   string   `toml:"log_format"` // "json" or "text" (default: "text")
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
		for _, key := range []string{"port", "host", "data", "base_url", "cors_origins", "trust_proxy", "tunnel", "log_format"} {
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
	return nil
}

// Merge combines defaults, file config, env config, and flag overrides.
// Precedence: flags > env > file > defaults.
// fileSet and envSet indicate which fields were explicitly set in the file/env layers.
// flagSet indicates which flags were explicitly set by the user (not just defaults).
func Merge(defaults, file Config, fileSet map[string]bool, env Config, envSet map[string]bool, flags Config, flagSet map[string]bool) Config {
	result := defaults

	// Layer 1: file overrides defaults (only fields explicitly set in file)
	if fileSet["port"] {
		result.Port = file.Port
	}
	if fileSet["host"] {
		result.Host = file.Host
	}
	if fileSet["data"] {
		result.Data = file.Data
	}
	if fileSet["base_url"] {
		result.BaseURL = file.BaseURL
	}
	if fileSet["cors_origins"] {
		result.CORSOrigins = file.CORSOrigins
	}
	if fileSet["trust_proxy"] {
		result.TrustProxy = file.TrustProxy
	}
	if fileSet["tunnel"] {
		result.Tunnel = file.Tunnel
	}
	if fileSet["log_format"] {
		result.LogFormat = file.LogFormat
	}

	// Layer 2: env overrides file
	if envSet["port"] {
		result.Port = env.Port
	}
	if envSet["host"] {
		result.Host = env.Host
	}
	if envSet["data"] {
		result.Data = env.Data
	}
	if envSet["base_url"] {
		result.BaseURL = env.BaseURL
	}
	if envSet["cors_origins"] {
		result.CORSOrigins = env.CORSOrigins
	}
	if envSet["trust_proxy"] {
		result.TrustProxy = env.TrustProxy
	}
	if envSet["tunnel"] {
		result.Tunnel = env.Tunnel
	}
	if envSet["log_format"] {
		result.LogFormat = env.LogFormat
	}

	// Layer 3: flags override env
	if flagSet["port"] {
		result.Port = flags.Port
	}
	if flagSet["host"] {
		result.Host = flags.Host
	}
	if flagSet["data"] {
		result.Data = flags.Data
	}
	if flagSet["base-url"] {
		result.BaseURL = flags.BaseURL
	}
	if flagSet["cors-origins"] {
		result.CORSOrigins = flags.CORSOrigins
	}
	if flagSet["trust-proxy"] {
		result.TrustProxy = flags.TrustProxy
	}
	if flagSet["tunnel"] {
		result.Tunnel = flags.Tunnel
	}
	if flagSet["log-format"] {
		result.LogFormat = flags.LogFormat
	}

	return result
}
