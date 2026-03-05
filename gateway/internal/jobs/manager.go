package jobs

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/google/uuid"

	"github.com/graph-hunter/gateway/internal/engine"
	"github.com/graph-hunter/gateway/internal/upload"
	"github.com/graph-hunter/gateway/internal/ws"
)

// Status represents the state of a job.
type Status string

const (
	StatusPending    Status = "pending"
	StatusRunning    Status = "running"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
)

// Progress holds the latest ingestion progress for a job.
type Progress struct {
	Processed int `json:"processed"`
	Total     int `json:"total"`
	Entities  int `json:"entities"`
	Relations int `json:"relations"`
}

// Result holds the final ingestion result.
type Result struct {
	NewEntities    int                    `json:"new_entities"`
	NewRelations   int                    `json:"new_relations"`
	TotalEntities  int                    `json:"total_entities"`
	TotalRelations int                    `json:"total_relations"`
	Pagination     map[string]interface{} `json:"pagination,omitempty"`
}

// Job tracks a single ingestion job (file-based or query-based).
type Job struct {
	ID          string                 `json:"id"`
	UploadID    string                 `json:"upload_id,omitempty"`
	SessionID   string                 `json:"session_id"`
	Format      string                 `json:"format,omitempty"`
	QueryParams map[string]interface{} `json:"-"` // for ingest_query; not serialized
	Status      Status                 `json:"status"`
	Progress    Progress               `json:"progress"`
	Result      *Result                `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// Manager creates and tracks ingestion jobs.
type Manager struct {
	engine *engine.RustEngine
	store  *upload.DiskStore
	hub    *ws.Hub
	mu     sync.RWMutex
	jobs   map[string]*Job
}

// NewManager creates a new job manager.
func NewManager(eng *engine.RustEngine, store *upload.DiskStore, hub *ws.Hub) *Manager {
	return &Manager{
		engine: eng,
		store:  store,
		hub:    hub,
		jobs:   make(map[string]*Job),
	}
}

// Create creates a new file-based ingest job and starts processing in a goroutine.
func (m *Manager) Create(uploadID, format, sessionID string) (*Job, error) {
	job := &Job{
		ID:        uuid.New().String(),
		UploadID:  uploadID,
		SessionID: sessionID,
		Format:    format,
		Status:    StatusPending,
	}

	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()

	go m.run(job)

	return job, nil
}

// CreateQuery creates a new SIEM query-based ingest job and starts processing in a goroutine.
// params must include session_id, source ("sentinel" or "elastic"), and source-specific fields.
func (m *Manager) CreateQuery(sessionID string, params map[string]interface{}) (*Job, error) {
	if params == nil {
		params = make(map[string]interface{})
	}
	params["session_id"] = sessionID

	job := &Job{
		ID:          uuid.New().String(),
		SessionID:   sessionID,
		QueryParams: params,
		Status:      StatusPending,
	}

	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()

	go m.run(job)

	return job, nil
}

// Get returns a job by ID.
func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

func (m *Manager) run(job *Job) {
	m.setStatus(job, StatusRunning)

	var req engine.Request
	reqID := uuid.New().String()
	req.ID = reqID

	if job.QueryParams != nil {
		// SIEM query-based ingest
		req.Cmd = "ingest_query"
		req.Params = job.QueryParams
	} else {
		// File-based ingest
		fileInfo, ok := m.store.Get(job.UploadID)
		if !ok {
			m.setFailed(job, "upload not found: "+job.UploadID)
			return
		}
		req.Cmd = "ingest"
		req.Params = map[string]string{
			"session_id": job.SessionID,
			"file_path":  fileInfo.Path,
			"format":     job.Format,
		}
	}

	done := make(chan struct{})

	err := m.engine.Send(req, func(resp engine.Response) {
		switch resp.Type {
		case "progress":
			var p Progress
			if resp.Data != nil {
				_ = json.Unmarshal(*resp.Data, &p)
			}
			m.mu.Lock()
			job.Progress = p
			m.mu.Unlock()

			m.hub.Broadcast(ws.Event{
				Type: "ingest_progress",
				Data: map[string]interface{}{
					"job_id":   job.ID,
					"progress": p,
				},
			})

		case "result":
			var r Result
			if resp.Data != nil {
				_ = json.Unmarshal(*resp.Data, &r)
			}
			m.mu.Lock()
			job.Status = StatusCompleted
			job.Result = &r
			m.mu.Unlock()

			m.hub.Broadcast(ws.Event{
				Type: "job_completed",
				Data: map[string]interface{}{
					"job_id": job.ID,
					"result": r,
				},
			})
			close(done)

		case "error":
			m.setFailed(job, resp.Error)
			close(done)
		}
	})

	if err != nil {
		m.setFailed(job, "engine send failed: "+err.Error())
		return
	}

	<-done
}

func (m *Manager) setStatus(job *Job, status Status) {
	m.mu.Lock()
	job.Status = status
	m.mu.Unlock()
}

func (m *Manager) setFailed(job *Job, errMsg string) {
	m.mu.Lock()
	job.Status = StatusFailed
	job.Error = errMsg
	m.mu.Unlock()

	m.hub.Broadcast(ws.Event{
		Type: "job_failed",
		Data: map[string]interface{}{
			"job_id": job.ID,
			"error":  errMsg,
		},
	})

	log.Printf("job %s failed: %s", job.ID, errMsg)
}
