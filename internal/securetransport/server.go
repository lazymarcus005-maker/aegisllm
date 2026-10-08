package securetransport

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// NewHTTPServer returns a bounded server for local fixtures and operator
// endpoints. Explicit timeouts prevent a slow client from holding a socket
// indefinitely while retaining normal streaming response behavior.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// ServeHTTPServer serves HTTP or HTTPS and shuts down gracefully on the
// process termination signals used by the release fixtures and services.
func ServeHTTPServer(server *http.Server, certFile, keyFile string) error {
	if server == nil {
		return errors.New("HTTP server is required")
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	shutdown := make(chan struct{})
	shutdownResult := make(chan error, 1)
	go func() {
		select {
		case <-stop:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			shutdownResult <- server.Shutdown(ctx)
			cancel()
		case <-shutdown:
		}
	}()
	var err error
	if certFile != "" || keyFile != "" {
		err = server.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = server.ListenAndServe()
	}
	close(shutdown)
	signal.Stop(stop)
	if errors.Is(err, http.ErrServerClosed) {
		select {
		case shutdownErr := <-shutdownResult:
			return shutdownErr
		default:
			return nil
		}
	}
	return err
}
