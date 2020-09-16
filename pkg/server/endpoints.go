package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/netsoc/iam/pkg/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	JSONErrResponse(w, errors.New("API endpoint not found"), http.StatusNotFound)
}
func (s *Server) apiMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	JSONErrResponse(w, errors.New("method not allowed on API endpoint"), http.StatusNotFound)
}

func (s *Server) apiOneUser(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(keyUser).(*models.User)
	claims := r.Context().Value(keyClaims).(*models.UserClaims)
	validAdmin := actor.IsAdmin && claims.ExpiresAt.After(time.Now())

	username := mux.Vars(r)["username"]
	// Only admins can access other users
	if (username != models.SelfUser && username != actor.Username) && !validAdmin {
		JSONErrResponse(w, models.ErrAdminRequired, 0)
		return
	}

	var user, patch models.User
	if r.Method == http.MethodPatch {
		if err := ParseJSONBody(&patch, w, r); err != nil {
			return
		}

		if !validAdmin && patch.SaveRequiresAdmin() {
			JSONErrResponse(w, models.ErrAdminRequired, 0)
			return
		}
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if username == models.SelfUser {
			user = *actor
		} else if err := tx.First(&user, "username = ?", username).Error; err != nil {
			return fmt.Errorf("failed to fetch user from database: %v", err)
		}

		switch r.Method {
		case http.MethodDelete:
			t := tx
			if !s.config.DB.SoftDelete {
				t = tx.Unscoped()
			}

			if err := t.Delete(&user).Error; err != nil {
				return fmt.Errorf("failed to delete to database: %w", err)
			}
		case http.MethodPatch:
			if err := tx.Model(user).Updates(&patch).Error; err != nil {
				return fmt.Errorf("failed to write to database: %w", err)
			}
		default:
		}

		return nil
	}); err != nil {
		JSONErrResponse(w, err, 0)
		return
	}

	user.Clean()
	JSONResponse(w, user, http.StatusOK)
}

func (s *Server) apiGetUsers(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	if err := s.db.Omit("password").Find(&users).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to fetch users from database: %v", err), 0)
		return
	}

	JSONResponse(w, users, http.StatusOK)
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	admin := r.Context().Value(keyUser)
	if admin != nil {
		claims := r.Context().Value(keyClaims).(*models.UserClaims)
		if time.Now().After(claims.ExpiresAt.Time) {
			JSONErrResponse(w, models.ErrTokenExpired, 0)
			return
		}
	}

	var user models.User
	if err := ParseJSONBody(&user, w, r); err != nil {
		return
	}

	if admin == nil && user.SaveRequiresAdmin() {
		JSONErrResponse(w, models.ErrAdminRequired, 0)
		return
	}

	if err := s.db.Create(&user).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	user.Clean()
	JSONResponse(w, user, http.StatusCreated)
}

type loginUserReq struct {
	Password string `json:"password"`
}
type loginUserRes struct {
	Token string `json:"token"`
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := s.db.First(&user, "username = ?", mux.Vars(r)["username"]).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %v", err), 0)
		return
	}

	var req loginUserReq
	if err := ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			JSONErrResponse(w, errors.New("incorrect password"), http.StatusUnauthorized)
			return
		}

		JSONErrResponse(w, err, 0)
		return
	}

	t, err := user.GenerateToken(s.config.JWT.Key, s.config.JWT.Issuer, user.Renewed.Add(s.config.JWT.LoginValidity))
	if err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
		return
	}

	JSONResponse(w, loginUserRes{t}, http.StatusOK)
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(keyUser).(*models.User)
	claims := r.Context().Value(keyClaims).(*models.UserClaims)
	validAdmin := actor.IsAdmin && claims.ExpiresAt.After(time.Now())

	username := mux.Vars(r)["username"]
	if username != models.SelfUser {
		// Only admins can logout other users
		if username != actor.Username && !validAdmin {
			JSONErrResponse(w, models.ErrAdminRequired, 0)
			return
		}
	} else {
		username = actor.Username
	}

	err := s.db.
		Model(&models.User{}).
		Where("username = ?", username).
		UpdateColumn("token_version", gorm.Expr("token_version + ?", 1)).Error
	if err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
