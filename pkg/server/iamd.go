package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/netsoc/iam/pkg/models"
	"golang.org/x/net/context"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Server represents the iamd server
type Server struct {
	config Config

	db   *gorm.DB
	http *http.Server
}

// NewServer creates a new iamd server
func NewServer(config Config) *Server {
	router := mux.NewRouter()
	h := &http.Server{
		Addr:    config.HTTPAddress,
		Handler: handlers.CustomLoggingHandler(nil, router, writeAccessLog),
	}

	s := &Server{
		config: config,

		http: h,
	}

	router.HandleFunc("/v1/users", s.apiGetUsers).Methods("GET")
	router.HandleFunc("/v1/users", s.apiCreateUser).Methods("POST")
	router.HandleFunc("/v1/users/{username}", s.apiOneUser).Methods("GET", "DELETE", "PATCH")

	router.NotFoundHandler = http.HandlerFunc(s.apiNotFound)
	router.MethodNotAllowedHandler = http.HandlerFunc(s.apiMethodNotAllowed)

	return s
}

// Start starts the iamd server
func (s *Server) Start() error {
	var err error
	s.db, err = gorm.Open(postgres.Open(s.config.DB.DSN), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open connection to database: %w", err)
	}

	s.db.AutoMigrate(&models.User{})

	err = s.http.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	return nil
}

// Stop shuts down the iamd server
func (s *Server) Stop() error {
	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shut down HTTP server: %w", err)
	}

	db, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get SQL DB: %w", err)
	}

	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	return nil
}
