package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gorilla/handlers"
	"github.com/netsoc/iam/pkg/models"
	log "github.com/sirupsen/logrus"
)

type key int

const (
	keyClaims key = iota
	keyUser
)

var tokenHeaderRegex = regexp.MustCompile(`^Bearer\s+(\S+)$`)

// JSONResponse Sends a JSON payload in response to a HTTP request
func JSONResponse(w http.ResponseWriter, v interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.WithField("err", err).Error("Failed to serialize JSON payload")

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Failed to serialize JSON payload")
	}
}

type jsonError struct {
	Message string `json:"message"`
}

// JSONErrResponse Sends an `error` as a JSON object with a `message` property
func JSONErrResponse(w http.ResponseWriter, err error, statusCode int) {
	log.WithError(err).Error("Error while processing request")

	w.Header().Set("Content-Type", "application/problem+json")
	if statusCode == 0 {
		statusCode = models.ErrToStatus(err)
	}
	w.WriteHeader(statusCode)

	enc := json.NewEncoder(w)
	enc.Encode(jsonError{err.Error()})
}

// ParseJSONBody attempts to parse the request body as JSON
func ParseJSONBody(v interface{}, w http.ResponseWriter, r *http.Request) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to parse request body: %w", err), http.StatusBadRequest)
		return err
	}

	return nil
}

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
			JSONErrResponse(w, err, http.StatusUnauthorized)
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

	log.WithFields(log.Fields{
		"uid":     uid,
		"agent":   params.Request.UserAgent(),
		"status":  params.StatusCode,
		"resSize": params.Size,
	}).Debugf("%v %v", params.Request.Method, params.URL.RequestURI())
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
				JSONErrResponse(w, models.ErrTokenRequired, 0)
			} else {
				next.ServeHTTP(w, r)
			}
			return
		}

		opts := []jwt.ParserOption{jwt.WithIssuer(m.Server.config.JWT.Issuer)}
		if !m.CheckExpired {
			opts = append(opts, jwt.WithLeeway(math.MaxInt64))
		}

		_, err := jwt.Parse(matches[1], func(t *jwt.Token) (interface{}, error) {
			return m.Server.config.JWT.Key, nil
		}, opts...)
		if err != nil {
			JSONErrResponse(w, err, http.StatusUnauthorized)
			return
		}

		claims := r.Context().Value(keyClaims).(*models.UserClaims)
		id, err := strconv.Atoi(claims.Subject)
		if err != nil {
			JSONErrResponse(w, fmt.Errorf("failed to parse user ID: %w", err), 0)
			return
		}

		var user models.User
		if err := m.Server.db.First(&user, id).Error; err != nil {
			JSONErrResponse(w, fmt.Errorf("failed to fetch user: %w", err), 0)
			return
		}

		if claims.Version != user.TokenVersion {
			JSONErrResponse(w, models.ErrTokenExpired, 0)
			return
		}

		if m.RequireAdmin && !user.IsAdmin {
			JSONErrResponse(w, models.ErrAdminRequired, 0)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), keyUser, &user))

		next.ServeHTTP(w, r)
	})
}
