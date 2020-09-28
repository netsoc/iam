package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	httpswagger "github.com/devplayer0/http-swagger"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/netsoc/iam/internal/data"
	"github.com/netsoc/iam/pkg/ma1sd"
	"github.com/netsoc/iam/pkg/models"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	mail "github.com/xhit/go-simple-mail/v2"
	"golang.org/x/net/context"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Server represents the iamd server
type Server struct {
	config Config

	db   *gorm.DB
	smtp *mail.SMTPServer
	http *http.Server

	router *mux.Router
	ma1sd  *ma1sd.MA1SD
}

// NewServer creates a new iamd server
func NewServer(config Config) *Server {
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: config.HTTP.CORS.AllowedOrigins,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	router := mux.NewRouter()
	h := &http.Server{
		Addr:    config.HTTP.ListenAddress,
		Handler: claimsMiddleware(handlers.CustomLoggingHandler(nil, corsMiddleware.Handler(router), writeAccessLog)),
	}

	s := &Server{
		config: config,

		http: h,

		router: router,
		ma1sd:  ma1sd.NewMA1SD(config.MA1SD.Domain, nil),
	}

	apiR := router.PathPrefix("/v1").Subrouter()

	apiR.HandleFunc("/users/{username}/login", s.apiLogin).Methods("POST")

	// Only non-expired admins can access
	mgmtAuth := authMiddleware{
		Server: s,

		CheckExpired: true,
		RequireAdmin: true,
	}
	mgmtR := apiR.NewRoute().Subrouter()
	mgmtR.Use(mgmtAuth.Middleware)
	mgmtR.HandleFunc("/users", s.apiGetUsers).Methods("GET")
	mgmtR.HandleFunc("/users/{username}/token", s.apiIssueToken).Methods("POST")

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

	// Some auth required, can be expired and not admin
	defaultAuth := authMiddleware{
		Server: s,
	}
	authR := apiR.NewRoute().Subrouter()
	authR.Use(defaultAuth.Middleware)
	authR.HandleFunc("/users/{username}", s.apiOneUser).Methods("GET", "DELETE", "PATCH")
	authR.HandleFunc("/users/{username}/login", s.apiLogout).Methods("DELETE")

	// Token must be valid
	validAuth := authMiddleware{
		Server: s,

		CheckExpired: true,
	}
	validR := apiR.NewRoute().Subrouter()
	validR.Use(validAuth.Middleware)
	validR.HandleFunc("/users/self/token", s.apiValidateToken).Methods("GET")

	verificationR := apiR.NewRoute().Subrouter()
	verificationR.Use((&emailTokenMiddleware{s, models.AudVerification}).Middleware)
	verificationR.HandleFunc("/users/{username}/login", s.apiVerify).Methods("PATCH")

	resetR := apiR.NewRoute().Subrouter()
	resetR.Use((&emailTokenMiddleware{s, models.AudPasswordReset}).Middleware)
	resetR.HandleFunc("/users/{username}/login", s.apiResetPassword).Methods("PUT")

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(data.AssetFile())))
	router.PathPrefix("/swagger/").Handler(httpswagger.Handler(
		httpswagger.URL("/static/api.yaml"),
		httpswagger.PersistAuth(true),
	))

	router.HandleFunc("/health", s.healthCheck)

	router.PathPrefix(config.MA1SD.BaseURL).Handler(http.StripPrefix(config.MA1SD.BaseURL, s.ma1sd))

	router.NotFoundHandler = http.HandlerFunc(s.apiNotFound)
	router.MethodNotAllowedHandler = http.HandlerFunc(s.apiMethodNotAllowed)

	return s
}

// Start starts the iamd server
func (s *Server) Start() error {
	if err := s.initEmail(); err != nil {
		return fmt.Errorf("failed to initialize SMTP client: %w", err)
	}

	var err error
	pg := &s.config.PostgreSQL
	dsn := strings.TrimSpace(fmt.Sprintf("host=%v user=%v password=%v dbname=%v TimeZone=%v %v",
		pg.Host,
		pg.User,
		pg.Password,
		pg.Database,
		pg.TimeZone,
		pg.DSNExtra,
	))
	s.db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open connection to database: %w", err)
	}

	s.db.AutoMigrate(&models.User{})

	var count int64
	if err := s.db.Model(&models.User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	if count == 0 {
		root := models.User{
			Username:  "root",
			Email:     "root@tcd.ie",
			Password:  s.config.RootPassword,
			FirstName: "Root",
			LastName:  "Netsoc",

			Verified: true,
			Renewed:  time.Now(),
			IsAdmin:  true,
		}

		log.WithField("password", root.Password).Info("Database empty, creating root user")
		if err := s.db.Create(&root).Error; err != nil {
			return fmt.Errorf("failed to create root user: %w", err)
		}
	}

	s.ma1sd.DB = s.db

	err = s.http.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
