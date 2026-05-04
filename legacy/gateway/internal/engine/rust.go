package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
)

// Request is a JSON command sent to the Rust CLI via stdin.
type Request struct {
	ID     string      `json:"id"`
	Cmd    string      `json:"cmd"`
	Params interface{} `json:"params"`
}

// Response is a JSON message received from the Rust CLI via stdout.
type Response struct {
	ID      string           `json:"id"`
	Type    string           `json:"type"` // "ready", "result", "error", "progress"
	Data    *json.RawMessage `json:"data,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// Callback receives responses (progress, result, error) for a pending request.
type Callback func(resp Response)

// RustEngine manages the Rust CLI child process and routes responses by request ID.
type RustEngine struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	mu      sync.Mutex // protects stdin writes
	pending sync.Map   // id -> Callback
	done    chan struct{}
}

// New spawns the Rust CLI binary and waits for the "ready" signal.
func New(binPath string) (*RustEngine, error) {
	cmd := exec.Command(binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = nil // discard stderr or could log it

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start CLI: %w", err)
	}

	e := &RustEngine{
		cmd:   cmd,
		stdin: stdin,
		done:  make(chan struct{}),
	}

	// Wait for the "ready" message before returning.
	readyCh := make(chan error, 1)
	go e.readLoop(stdout, readyCh)

	if err := <-readyCh; err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("waiting for ready: %w", err)
	}

	return e, nil
}

// Send sends a command to the Rust CLI and registers a callback for responses.
func (e *RustEngine) Send(req Request, cb Callback) error {
	e.pending.Store(req.ID, cb)

	data, err := json.Marshal(req)
	if err != nil {
		e.pending.Delete(req.ID)
		return fmt.Errorf("marshal request: %w", err)
	}

	e.mu.Lock()
	_, err = fmt.Fprintf(e.stdin, "%s\n", data)
	e.mu.Unlock()

	if err != nil {
		e.pending.Delete(req.ID)
		return fmt.Errorf("write to stdin: %w", err)
	}

	return nil
}

// Close shuts down the Rust CLI process.
func (e *RustEngine) Close() {
	e.stdin.Close()
	<-e.done
	_ = e.cmd.Wait()
}

// readLoop reads newline-delimited JSON from the CLI's stdout.
func (e *RustEngine) readLoop(r io.Reader, readyCh chan<- error) {
	defer close(e.done)
	scanner := bufio.NewScanner(r)
	// Allow large lines (up to 64 MB) for big results.
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)

	readySent := false

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			log.Printf("engine: invalid JSON from CLI: %s", string(line))
			continue
		}

		// Handle "ready" signal
		if resp.Type == "ready" && !readySent {
			readySent = true
			readyCh <- nil
			continue
		}

		// Route response to pending callback
		if val, ok := e.pending.Load(resp.ID); ok {
			cb := val.(Callback)
			cb(resp)
			// Remove callback on terminal responses
			if resp.Type == "result" || resp.Type == "error" {
				e.pending.Delete(resp.ID)
			}
		}
	}

	if !readySent {
		readyCh <- fmt.Errorf("CLI exited before sending ready")
	}
}
