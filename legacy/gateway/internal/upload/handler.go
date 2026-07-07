package upload

import (
	"io"

	"github.com/gofiber/fiber/v2"
)

// Handler returns a Fiber handler for POST /api/upload.
// Streams the multipart file to disk using constant memory (io.Copy).
func Handler(store *DiskStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		fileHeader, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing 'file' field in multipart form",
			})
		}

		src, err := fileHeader.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to open uploaded file",
			})
		}
		defer src.Close()

		info, dst, err := store.Create(fileHeader.Filename)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to create temp file",
			})
		}

		written, err := io.Copy(dst, src)
		dst.Close()
		if err != nil {
			store.Remove(info.ID)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to save file",
			})
		}

		store.Finalize(info.ID, written)

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"upload_id": info.ID,
			"size":      written,
		})
	}
}
