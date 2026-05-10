package main

import (
	"log/slog"
	"os"

	"github.com/Yongbeom-Kim/express-mitm/internal/mitmserver"
)

func main() {
	server := mitmserver.NewMitmServer(":16326")
	if err := server.Listen(); err != nil {
		slog.Error("MITM server error", "error", err)
		os.Exit(1)
	}
}
