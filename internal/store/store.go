package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

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
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
		created_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{db: db, cancel: cancel}

	// Run cleanup once at startup
	s.Cleanup()

	// Start periodic cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Cleanup()
			}
		}
	}()

	return s, nil
}

func (s *Store) Create(id string, encrypted, iv []byte, viewsLeft int, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO secrets (id, encrypted, iv, views_left, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, encrypted, iv, viewsLeft, expiresAt.Unix(),
	)
	return err
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

func (s *Store) Delete(id string) error {
	_, err := s.db.Exec(`DELETE FROM secrets WHERE id = ?`, id)
	return err
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
