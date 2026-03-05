package upload

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

// FileInfo holds metadata about an uploaded file.
type FileInfo struct {
	ID   string `json:"upload_id"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// DiskStore manages temporary uploaded files on disk.
type DiskStore struct {
	dir   string
	mu    sync.RWMutex
	files map[string]*FileInfo
}

// NewDiskStore creates a store that saves files under dir.
func NewDiskStore(dir string) *DiskStore {
	_ = os.MkdirAll(dir, 0o755)
	return &DiskStore{
		dir:   dir,
		files: make(map[string]*FileInfo),
	}
}

// Create returns a new file path and upload ID for writing.
func (s *DiskStore) Create(originalName string) (*FileInfo, *os.File, error) {
	id := uuid.New().String()
	ext := filepath.Ext(originalName)
	filename := id + ext
	path := filepath.Join(s.dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create file: %w", err)
	}

	info := &FileInfo{ID: id, Path: path}
	s.mu.Lock()
	s.files[id] = info
	s.mu.Unlock()

	return info, f, nil
}

// Finalize records the final size after upload completes.
func (s *DiskStore) Finalize(id string, size int64) {
	s.mu.Lock()
	if info, ok := s.files[id]; ok {
		info.Size = size
	}
	s.mu.Unlock()
}

// Get returns file info by upload ID.
func (s *DiskStore) Get(id string) (*FileInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.files[id]
	return info, ok
}

// Remove deletes the file from disk and store.
func (s *DiskStore) Remove(id string) {
	s.mu.Lock()
	info, ok := s.files[id]
	if ok {
		_ = os.Remove(info.Path)
		delete(s.files, id)
	}
	s.mu.Unlock()
}
