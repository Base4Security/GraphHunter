package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/graph-hunter/gateway/internal/engine"
	"github.com/graph-hunter/gateway/internal/jobs"
	"github.com/graph-hunter/gateway/internal/upload"
	"github.com/graph-hunter/gateway/internal/ws"
)

// Run starts the Fiber HTTP server with all routes.
func Run() {
	cliBin := os.Getenv("GRAPH_HUNTER_CLI")
	if cliBin == "" {
		cliBin = "graph_hunter_cli"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "uploads"
	}

	// Initialize subsystems
	rustEngine, err := engine.New(cliBin)
	if err != nil {
		log.Fatalf("failed to start Rust engine: %v", err)
	}
	defer rustEngine.Close()

	store := upload.NewDiskStore(uploadDir)
	hub := ws.NewHub()
	go hub.Run()

	jobManager := jobs.NewManager(rustEngine, store, hub)

	app := fiber.New(fiber.Config{
		StreamRequestBody: true,
		BodyLimit:         2 * 1024 * 1024 * 1024, // 2 GB
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Content-Type",
	}))

	// Routes
	api := app.Group("/api")

	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	api.Post("/upload", upload.Handler(store))
	api.Post("/sessions", jobs.SessionCreateHandler(rustEngine))
	api.Post("/jobs", jobs.CreateHandler(jobManager))
	api.Post("/ingest/query", jobs.CreateQueryHandler(jobManager))
	api.Get("/jobs/:id", jobs.StatusHandler(jobManager))

	api.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	api.Get("/ws", websocket.New(func(c *websocket.Conn) {
		ws.HandleConnection(hub, c)
	}))

	log.Printf("Graph Hunter Gateway listening on :%s", port)
	if err := app.Listen(fmt.Sprintf(":%s", port)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
