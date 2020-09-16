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

	apiR := router.PathPrefix("/v1").Subrouter()

	apiR.HandleFunc("/users/{username}/login", s.apiLoginUser).Methods("POST")

	// Only non-expired admins can access
	mgmtAuth := authMiddleware{
		Server: s,

		CheckExpired: true,
		RequireAdmin: true,
	}
	mgmtR := apiR.NewRoute().Subrouter()
	mgmtR.Use(mgmtAuth.Middleware)
	mgmtR.HandleFunc("/users", s.apiGetUsers).Methods("GET")

	// Either the user is unauthorised _or_ they are a valid admin
	optMgmtAuth := authMiddleware{
		Server: s,

		Optional:     true,
		CheckExpired: true,
		RequireAdmin: true,
	}
	optMgmtR := apiR.NewRoute().Subrouter()
	optMgmtR.Use(optMgmtAuth.Middleware)
	optMgmtR.HandleFunc("/users", s.apiCreateUser).Methods("POST")

	// Fetch a user (expiry to be checked later if needed)
	fetchAuth := authMiddleware{
		Server: s,

		FetchUser: true,
	}
	fetchR := apiR.NewRoute().Subrouter()
	fetchR.Use(fetchAuth.Middleware)
	fetchR.HandleFunc("/users/{username}", s.apiOneUser).Methods("GET", "DELETE", "PATCH")

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
