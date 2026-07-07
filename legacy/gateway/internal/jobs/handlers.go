package jobs

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"

	"github.com/graph-hunter/gateway/internal/engine"
)

// CreateRequest is the JSON body for POST /api/jobs.
type CreateRequest struct {
	UploadID  string `json:"upload_id"`
	Format    string `json:"format"`
	SessionID string `json:"session_id"`
}

// CreateHandler returns a Fiber handler for POST /api/jobs.
func CreateHandler(m *Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req CreateRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid JSON body",
			})
		}

		if req.UploadID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "upload_id is required",
			})
		}

		if req.SessionID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "session_id is required",
			})
		}

		if req.Format == "" {
			req.Format = "auto"
		}

		job, err := m.Create(req.UploadID, req.Format, req.SessionID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"id":     job.ID,
			"status": job.Status,
		})
	}
}

// CreateQueryHandler returns a Fiber handler for POST /api/ingest/query (SIEM query-based ingest).
func CreateQueryHandler(m *Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var params map[string]interface{}
		if err := json.Unmarshal(c.Body(), &params); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid JSON body",
			})
		}
		sessionID, _ := params["session_id"].(string)
		if sessionID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "session_id is required",
			})
		}
		source, _ := params["source"].(string)
		if source != "sentinel" && source != "elastic" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "source must be 'sentinel' or 'elastic'",
			})
		}
		job, err := m.CreateQuery(sessionID, params)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"id":     job.ID,
			"status": job.Status,
		})
	}
}

// SessionCreateRequest is the JSON body for POST /api/sessions.
type SessionCreateRequest struct {
	Name string `json:"name"`
}

// SessionCreateHandler returns a Fiber handler for POST /api/sessions.
func SessionCreateHandler(eng *engine.RustEngine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req SessionCreateRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid JSON body",
			})
		}
		if req.Name == "" {
			req.Name = "web-session"
		}

		result, err := eng.CreateSession(req.Name)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Status(fiber.StatusCreated).JSON(result)
	}
}

// StatusHandler returns a Fiber handler for GET /api/jobs/:id.
func StatusHandler(m *Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := c.Params("id")
		job, ok := m.Get(id)
		if !ok {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "job not found",
			})
		}

		return c.JSON(job)
	}
}
