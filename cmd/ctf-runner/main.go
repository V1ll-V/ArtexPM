package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Autumn-27/artex/ctfrunner"
)

func main() {
	token := os.Getenv("ARTEX_CTF_RUNNER_TOKEN")
	if len(token) < 24 {
		log.Fatal("ARTEX_CTF_RUNNER_TOKEN must contain at least 24 characters")
	}
	image := os.Getenv("ARTEX_CTF_TOOL_IMAGE")
	if image == "" {
		image = "autumn27/artex-ctf-tools:20261107"
	}
	s := &ctfrunner.Server{Engine: ctfrunner.DockerEngine("/var/run/docker.sock", image), Token: token, StateDir: "/state"}
	go func() {
		for range time.Tick(time.Minute) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			s.Collect(ctx, time.Now().Add(-time.Hour))
			cancel()
		}
	}()
	log.Fatal((&http.Server{Addr: ":8790", Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}
