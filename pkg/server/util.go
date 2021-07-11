package server

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gorilla/handlers"
	"github.com/netsoc/iam/pkg/models"
	"github.com/netsoc/iam/pkg/util"
	log "github.com/sirupsen/logrus"
)

type key int

const (
	keyClaims key = iota
	keyUser
)

var (
	tokenHeaderRegex = regexp.MustCompile(`^Bearer\s+(\S+)$`)
)

// Extract the (unverified!) claims
func claimsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matches := tokenHeaderRegex.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(matches) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		t, _, err := jwt.NewParser().ParseUnverified(matches[1], &models.UserClaims{})
		if err != nil {
			util.JSONErrResponse(w, err, http.StatusUnauthorized)
			return
		}

		claims := t.Claims.(*models.UserClaims)
		r = r.WithContext(context.WithValue(r.Context(), keyClaims, claims))

		next.ServeHTTP(w, r)
	})
}

func writeAccessLog(w io.Writer, params handlers.LogFormatterParams) {
	var uid string
	c := params.Request.Context().Value(keyClaims)
	if c != nil {
		uid = c.(*models.UserClaims).Subject
	}

	level := log.DebugLevel
	if params.URL.Path == "/health" {
		level = log.TraceLevel
	}
	log.StandardLogger().
		WithFields(log.Fields{
			"uid":     uid,
			"agent":   params.Request.UserAgent(),
			"status":  params.StatusCode,
			"resSize": params.Size,
		}).
		Logf(level, "%v %v", params.Request.Method, params.URL.RequestURI())
}

type authMiddleware struct {
	Server *Server

	Optional, CheckExpired, RequireAdmin bool
}

func (m *authMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matches := tokenHeaderRegex.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(matches) == 0 {
			if !m.Optional {
				util.JSONErrResponse(w, models.ErrTokenRequired, 0)
			} else {
				next.ServeHTTP(w, r)
			}
			return
		}

		opts := []jwt.ParserOption{
			jwt.WithIssuer(m.Server.config.JWT.Issuer),
			jwt.WithAudience(models.AudAuth),
		}
		if !m.CheckExpired {
			opts = append(opts, jwt.WithLeeway(math.MaxInt64))
		}

		_, err := jwt.Parse(matches[1], m.Server.config.JWTKeyFunc(), opts...)
		if err != nil {
			util.JSONErrResponse(w, err, http.StatusUnauthorized)
			return
		}

		claims := r.Context().Value(keyClaims).(*models.UserClaims)
		id, err := strconv.Atoi(claims.Subject)
		if err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to parse user ID: %w", err), 0)
			return
		}

		var user models.User
		if err := m.Server.db.First(&user, id).Error; err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to fetch user: %w", err), 0)
			return
		}

		if claims.Version != user.TokenVersion {
			util.JSONErrResponse(w, models.ErrTokenExpired, 0)
			return
		}

		if m.RequireAdmin && !*user.IsAdmin {
			util.JSONErrResponse(w, models.ErrAdminRequired, 0)
			return
		}

		// No need to check if the user is verified, we don't allow login without the account being verified!

		r = r.WithContext(context.WithValue(r.Context(), keyUser, &user))
		next.ServeHTTP(w, r)
	})
}

type emailTokenMiddleware struct {
	Server *Server

	Audience string
}

func (m *emailTokenMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matches := tokenHeaderRegex.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(matches) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		t, err := jwt.ParseWithClaims(matches[1], &models.EmailClaims{}, m.Server.config.JWTKeyFunc(),
			jwt.WithIssuer(m.Server.config.JWT.Issuer),
			jwt.WithAudience(m.Audience),
		)
		if err != nil {
			util.JSONErrResponse(w, err, http.StatusUnauthorized)
			return
		}

		claims := t.Claims.(*models.EmailClaims)
		id, err := strconv.Atoi(claims.Subject)
		if err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to parse user ID: %w", err), 0)
			return
		}

		var user models.User
		if err := m.Server.db.First(&user, id).Error; err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to fetch user: %w", err), 0)
			return
		}

		if claims.Version != user.TokenVersion {
			util.JSONErrResponse(w, models.ErrTokenExpired, 0)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), keyUser, &user))
		next.ServeHTTP(w, r)
	})
}
