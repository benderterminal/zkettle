package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// hashToken returns the SHA-256 hex digest of a delete token.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

var ErrNotFound = errors.New("secret not found")
var ErrExpired = errors.New("secret expired or consumed")

type SecretMeta struct {
	ID        string
	ViewsLeft int
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Store struct {
	db     *sql.DB
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	timer *time.Timer
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		encrypted BLOB NOT NULL,
		iv BLOB NOT NULL,
		views_left INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (unixepoch()),
		delete_token TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	// Migrate: add delete_token column if missing (pre-existing databases)
	db.Exec(`ALTER TABLE secrets ADD COLUMN delete_token TEXT NOT NULL DEFAULT ''`)

	// Index for efficient expiry cleanup queries
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_expires ON secrets(expires_at)`)

	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{db: db, ctx: ctx, cancel: cancel}

	// Run cleanup once at startup, then schedule next
	s.Cleanup()

	// Background goroutine waits for context cancellation to stop the timer
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.mu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Unlock()
	}()

	s.scheduleNextCleanup()

	return s, nil
}

// scheduleNextCleanup queries the nearest expiry and sets a timer to clean up at that time.
// The DB query runs outside the mutex; only timer operations are locked.
// Safe to call after Close() — returns immediately if the context is cancelled.
func (s *Store) scheduleNextCleanup() {
	if s.ctx.Err() != nil {
		return // store is closed
	}

	var nextExpiry sql.NullInt64
	err := s.db.QueryRow(`SELECT MIN(expires_at) FROM secrets WHERE expires_at > unixepoch()`).Scan(&nextExpiry)
	if err != nil || !nextExpiry.Valid {
		return // no secrets to clean up
	}

	delay := time.Until(time.Unix(nextExpiry.Int64, 0))
	if delay < 0 {
		delay = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring lock in case Close() raced
	if s.ctx.Err() != nil {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(delay, func() {
		if s.ctx.Err() != nil {
			return
		}
		if _, err := s.Cleanup(); err != nil {
			log.Printf("store: cleanup error: %v", err)
		}
		s.scheduleNextCleanup()
	})
}

func (s *Store) Create(id string, encrypted, iv []byte, viewsLeft int, expiresAt time.Time, deleteToken string) error {
	_, err := s.db.Exec(
		`INSERT INTO secrets (id, encrypted, iv, views_left, expires_at, delete_token) VALUES (?, ?, ?, ?, ?, ?)`,
		id, encrypted, iv, viewsLeft, expiresAt.Unix(), hashToken(deleteToken),
	)
	if err != nil {
		return err
	}

	// Reschedule cleanup if this new secret may expire sooner than the current timer
	s.scheduleNextCleanup()

	return nil
}

func (s *Store) Get(id string) (encrypted, iv []byte, err error) {
	// Atomic decrement + fetch using RETURNING
	err = s.db.QueryRow(
		`UPDATE secrets SET views_left = views_left - 1
		WHERE id = ? AND expires_at > unixepoch() AND views_left > 0
		RETURNING encrypted, iv`,
		id,
	).Scan(&encrypted, &iv)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	// Delete if views exhausted
	s.db.Exec(`DELETE FROM secrets WHERE id = ? AND views_left <= 0`, id)

	return encrypted, iv, nil
}

func (s *Store) Delete(id string, deleteToken string) error {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE id = ? AND delete_token = ?`, id, hashToken(deleteToken))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) List() ([]SecretMeta, error) {
	rows, err := s.db.Query(
		`SELECT id, views_left, expires_at, created_at FROM secrets WHERE expires_at > unixepoch()`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var expiresUnix, createdUnix int64
		if err := rows.Scan(&m.ID, &m.ViewsLeft, &expiresUnix, &createdUnix); err != nil {
			return nil, err
		}
		m.ExpiresAt = time.Unix(expiresUnix, 0)
		m.CreatedAt = time.Unix(createdUnix, 0)
		metas = append(metas, m)
	}
	return metas, rows.Err()
}

func (s *Store) Status(id string) error {
	var viewsLeft int
	var expiresAt int64
	err := s.db.QueryRow(
		`SELECT views_left, expires_at FROM secrets WHERE id = ?`,
		id,
	).Scan(&viewsLeft, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if viewsLeft <= 0 || expiresAt <= time.Now().Unix() {
		return ErrExpired
	}
	return nil
}

func (s *Store) Ping() error {
	return s.db.Ping()
}

func (s *Store) Cleanup() (int, error) {
	res, err := s.db.Exec(`DELETE FROM secrets WHERE expires_at <= unixepoch()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *Store) Close() {
	s.cancel()
	s.wg.Wait()
	s.db.Close()
}
