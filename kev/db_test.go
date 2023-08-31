package kev

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func Test_db_download(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test data"))
	}))
	defer ts.Close()
	tmpDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpDir)

	type fields struct {
		url      string
		cacheDir string
		clock    clock.Clock
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				url:      ts.URL,
				cacheDir: tmpDir,
				clock:    clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &db{
				url:      tt.fields.url,
				cacheDir: tt.fields.cacheDir,
				clock:    tt.fields.clock,
			}
			if err := d.download(); (err != nil) != tt.wantErr {
				t.Errorf("db.download() error = %v, wantErr %v", err, tt.wantErr)
			}

			body, err := os.ReadFile(d.dbFilePath())
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}
			if string(body) != "test data" {
				t.Errorf("unexpected file content: %s", string(body))
			}

			datetime, err := os.ReadFile(d.downloadAtFilePath())
			if err != nil {
				t.Fatalf("failed to read downloadAtFile: %v", err)
			}
			if string(datetime) != "2019-10-01T00:00:00Z" {
				t.Errorf("unexpected file content: %s", string(datetime))
			}
		})
	}
}

func Test_db_needsUpdate(t *testing.T) {
	tests := []struct {
		name                    string
		clock                   clock.Clock
		createCacheDir          bool
		dbFilePathContent       string
		downloadedAtFileContent string
		want                    bool
		wantErr                 bool
	}{
		{
			name:                    "24h have not passed",
			createCacheDir:          true,
			clock:                   clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			dbFilePathContent:       "test data",
			downloadedAtFileContent: "2019-10-01T00:00:00Z",
			want:                    false,
			wantErr:                 false,
		},
		{
			name:                    "24h have not passed and dbFile not found",
			createCacheDir:          true,
			clock:                   clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			downloadedAtFileContent: "2019-10-01T00:00:00Z",
			want:                    true,
			wantErr:                 false,
		},
		{
			name:              "24h have not passed and downloadedAtFile not found",
			createCacheDir:    true,
			clock:             clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			dbFilePathContent: "test data",
			want:              true,
			wantErr:           false,
		},
		{
			name:                    "24h have not passed and downloadedAtFile content is invalid",
			createCacheDir:          true,
			clock:                   clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			dbFilePathContent:       "test data",
			downloadedAtFileContent: "invalid2019-10-01T00:00:00Z",
			want:                    true,
			wantErr:                 false,
		},
		{
			name:                    "after 24h+",
			createCacheDir:          true,
			dbFilePathContent:       "test data",
			clock:                   clocktesting.NewFakeClock(time.Date(2019, 10, 2, 0, 0, 0, 1, time.UTC)),
			downloadedAtFileContent: "2019-10-01T00:00:00Z",
			want:                    true,
			wantErr:                 false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tempDir string
			var err error
			if tt.createCacheDir {
				tempDir, err = os.MkdirTemp("", "test")
				if err != nil {
					t.Fatalf("failed to create temporary dir: %v", err)
				}
				defer os.RemoveAll(tempDir)
			}
			d := &db{
				cacheDir: tempDir,
				clock:    tt.clock,
			}
			if tt.dbFilePathContent != "" {
				if err := os.WriteFile(d.dbFilePath(), []byte(tt.dbFilePathContent), 0644); err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
			}
			if tt.downloadedAtFileContent != "" {
				if err := os.WriteFile(d.downloadAtFilePath(), []byte(tt.downloadedAtFileContent), 0644); err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
			}
			got, err := d.needsUpdate()
			if (err != nil) != tt.wantErr {
				t.Errorf("db.needsUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("db.needsUpdate() = %v, want %v", got, tt.want)
			}

			if err := os.RemoveAll(tempDir); err != nil {
				t.Fatalf("failed to remove temporary dir: %v", err)
			}
		})
	}
}
