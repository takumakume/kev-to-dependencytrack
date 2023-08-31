package kev

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"k8s.io/utils/clock"
)

const (
	DEFAULT_KEV_CATALOG_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DB_FILE_NAME                 = "kev.json"
	DB_DOWNLOAD_AT_FILE_NAME     = "kev_downloaded_at"
)

type dbFetcher interface {
	// dbFilePath() string
	// downloadAtFilePath() string
	download() error
	needsUpdate() (bool, error)
	read() ([]byte, error)
}

type db struct {
	url      string
	cacheDir string
	clock    clock.Clock
}

type dbOpts struct {
	url      string
	cacheDir string
	clock    clock.Clock
}

type dbOpt func(*dbOpts)

// func withURL(url string) dbOpt {
// 	return func(opts *dbOpts) {
// 		opts.url = url
// 	}
// }

// func withCacheDir(cacheDir string) dbOpt {
// 	return func(opts *dbOpts) {
// 		opts.cacheDir = cacheDir
// 	}
// }

// func withClock(clock clock.Clock) dbOpt {
// 	return func(opts *dbOpts) {
// 		opts.clock = clock
// 	}
// }

func newDB(opts ...dbOpt) *db {
	o := &dbOpts{
		url:      DEFAULT_KEV_CATALOG_JSON_URL,
		cacheDir: filepath.Join(os.TempDir(), "kev-to-dependencytrack"),
		clock:    clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}

	return &db{
		url:      o.url,
		cacheDir: o.cacheDir,
		clock:    o.clock,
	}
}

func (d *db) dbFilePath() string {
	return filepath.Join(d.cacheDir, DB_FILE_NAME)
}

func (d *db) downloadAtFilePath() string {
	return filepath.Join(d.cacheDir, DB_DOWNLOAD_AT_FILE_NAME)
}

func (d *db) download() error {
	resp, err := http.Get(d.url)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kev db fetch error: %s: status %s", d.url, resp.Status)
	}

	if resp.Body == nil {
		return fmt.Errorf("kev db fetch error: %s: body is nil", d.url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(d.cacheDir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(d.dbFilePath(), body, 0644); err != nil {
		return err
	}

	date := d.clock.Now().Format(time.RFC3339)
	if err := os.WriteFile(d.downloadAtFilePath(), []byte(date), 0644); err != nil {
		return err
	}

	return nil
}

func (d *db) needsUpdate() (bool, error) {
	if _, err := os.Stat(d.dbFilePath()); err != nil {
		return true, nil
	}

	if _, err := os.Stat(d.downloadAtFilePath()); err != nil {
		return true, nil
	}

	downloadedAt, err := os.ReadFile(d.downloadAtFilePath())
	if err != nil {
		return false, err
	}

	t, err := time.Parse(time.RFC3339, string(downloadedAt))
	if err != nil {
		// expected format is RFC3339, need to update
		return true, nil
	}

	if d.clock.Now().Sub(t) > 24*time.Hour {
		return true, nil
	}

	return false, nil
}

func (d *db) read() ([]byte, error) {
	return os.ReadFile(d.dbFilePath())
}
