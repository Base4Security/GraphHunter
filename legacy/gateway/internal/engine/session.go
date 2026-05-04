package engine

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// CreateSessionResult holds the response from the CLI create_session command.
type CreateSessionResult struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
}

// CreateSession sends a create_session command to the CLI and waits for the result.
func (e *RustEngine) CreateSession(name string) (*CreateSessionResult, error) {
	reqID := uuid.New().String()
	req := Request{
		ID:  reqID,
		Cmd: "create_session",
		Params: map[string]string{
			"name": name,
		},
	}

	ch := make(chan Response, 1)
	if err := e.Send(req, func(resp Response) {
		ch <- resp
	}); err != nil {
		return nil, err
	}

	resp := <-ch
	if resp.Type == "error" {
		return nil, fmt.Errorf("CLI error: %s", resp.Error)
	}

	var result CreateSessionResult
	if resp.Data != nil {
		if err := json.Unmarshal(*resp.Data, &result); err != nil {
			return nil, fmt.Errorf("unmarshal session result: %w", err)
		}
	}

	return &result, nil
}
