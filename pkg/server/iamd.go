package server

import (
	"fmt"
	"net/http"
	"time"

	oapiMiddleware "github.com/go-openapi/runtime/middleware"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"gorm.io/gorm"

	"github.com/netsoc/iam/internal/data"
	"github.com/netsoc/iam/pkg/email"
	"github.com/netsoc/iam/pkg/ma1sd"
	"github.com/netsoc/iam/pkg/models"
)

// Server represents the iamd server
type Server struct {
	config Config

	db          *gorm.DB
	email       email.Sender
	http        *http.Server
	stopCleanup chan struct{}

	router    *mux.Router
	ma1sd     *ma1sd.MA1SD
	httpMA1SD *http.Server
}

// NewServer creates a new iamd server
func NewServer(config Config) (*Server, error) {
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
	}

	var err error
	s.email, err = email.NewSMTPSender(config.Mail, config.SMTP)
	if err != nil {
		return nil, fmt.Errorf("failed to create email sender: %w", err)
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
	mgmtR.HandleFunc("/users/id:{uid:[0-9]+}", s.apiGetUserByID).Methods("GET")
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
	router.PathPrefix("/swagger").Handler(oapiMiddleware.SwaggerUI(oapiMiddleware.SwaggerUIOpts{
		SpecURL: "/static/api.yaml",
		Path:    "swagger",
	}, nil))

	router.HandleFunc("/health", s.healthCheck)

	if config.MA1SD.HTTPAddress != "" {
		s.ma1sd = ma1sd.NewMA1SD(config.MA1SD.Domain, config.JWT.LoginValidity, nil)
		s.httpMA1SD = &http.Server{
			Addr:    config.MA1SD.HTTPAddress,
			Handler: http.StripPrefix(config.MA1SD.BaseURL, s.ma1sd),
		}
	}

	router.NotFoundHandler = http.HandlerFunc(s.apiNotFound)
	router.MethodNotAllowedHandler = http.HandlerFunc(s.apiMethodNotAllowed)

	return s, nil
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) CleanupUnverified() (int64, error) {
	tx := s.db
	if !s.config.PostgreSQL.SoftDelete {
		tx = s.db.Unscoped()
	}

	tx = tx.Delete(&models.User{}, "verified = ? AND created < ?", false, time.Now().Add(-s.config.Cleanup.MaxAge))
	return tx.RowsAffected, tx.Error
}
