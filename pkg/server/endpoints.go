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

		if !validAdmin {
			if err := patch.NonAdminSaveOK(s.config.ReservedUsernames); err != nil {
				JSONErrResponse(w, err, 0)
				return
			}
		}
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if username == models.SelfUser {
			user = *actor
		} else if err := tx.First(&user, "username = ?", username).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = models.ErrUserNotFound
			}

			return fmt.Errorf("failed to fetch user from database: %v", err)
		}

		switch r.Method {
		case http.MethodDelete:
			t := tx
			if !s.config.PostgreSQL.SoftDelete {
				t = tx.Unscoped()
			}

			if err := t.Delete(&user).Error; err != nil {
				return fmt.Errorf("failed to write to database: %w", err)
			}
		case http.MethodPatch:
			// Copy the user (so we can return the old one)
			updated := user

			// Invalidate existing tokens so the user must re-login
			if patch.Password != "" || patch.IsAdmin != user.IsAdmin || patch.Email != "" {
				patch.TokenVersion = user.TokenVersion + 1
				updated.TokenVersion = patch.TokenVersion
				if user.Email != "" {
					if err := tx.Model(&updated).Select("verified").Updates(&models.User{Verified: false}).Error; err != nil {
						return fmt.Errorf("failed to unverify user: %w", err)
					}
					if err := s.doSendVerificationEmail(&updated, r); err != nil {
						return err
					}
				}
			}

			if err := tx.Model(&updated).Updates(&patch).Error; err != nil {
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
	var user models.User
	if err := ParseJSONBody(&user, w, r); err != nil {
		return
	}

	if r.Context().Value(keyUser) == nil {
		if err := user.NonAdminSaveOK(s.config.ReservedUsernames); err != nil {
			JSONErrResponse(w, err, 0)
			return
		}
	}

	if err := s.db.Create(&user).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	if err := s.doSendVerificationEmail(&user, r); err != nil {
		JSONErrResponse(w, err, 0)
		return
	}

	user.Clean()
	JSONResponse(w, user, http.StatusCreated)
}

type passwordReq struct {
	Password string `json:"password"`
}
type tokenRes struct {
	Token string `json:"token"`
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := s.db.First(&user, "username = ?", mux.Vars(r)["username"]).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = models.ErrUserNotFound
		}

		JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %v", err), 0)
		return
	}

	if !user.Verified {
		JSONErrResponse(w, models.ErrUnverified, 0)
		return
	}

	var req passwordReq
	if err := ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			JSONErrResponse(w, models.ErrIncorrectPassword, 0)
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

	JSONResponse(w, tokenRes{t}, http.StatusOK)
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

func (s *Server) apiValidateToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type issueTokenReq struct {
	Duration string `json:"duration"`
}

func (s *Server) apiIssueToken(w http.ResponseWriter, r *http.Request) {
	var req issueTokenReq
	if err := ParseJSONBody(&req, w, r); err != nil {
		return
	}
	duration, err := time.ParseDuration(req.Duration)
	if err != nil {
		JSONErrResponse(w, errors.New("failed to parse duration"), http.StatusBadRequest)
		return
	}

	var user models.User
	if err := s.db.First(&user, "username = ?", mux.Vars(r)["username"]).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = models.ErrUserNotFound
		}

		JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %v", err), 0)
		return
	}

	t, err := user.GenerateToken(s.config.JWT.Key, s.config.JWT.Issuer, time.Now().Add(duration))
	if err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
		return
	}

	JSONResponse(w, tokenRes{t}, http.StatusOK)
}

func (s *Server) doSendVerificationEmail(user *models.User, r *http.Request) error {
	t, err := user.GenerateEmailToken(s.config.JWT.Key, s.config.JWT.Issuer, models.AudVerification,
		s.config.JWT.EmailValidity)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	tpl := EmailVerificationAPI
	if HTTPRequestAccepts(r, "text/html") {
		tpl = EmailVerificationUI
	}
	if err := s.SendEmail(tpl, EmailVerificationSubject, EmailUserInfo{user, t}); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
func (s *Server) apiVerify(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	u := r.Context().Value(keyUser)
	if u == nil {
		var user models.User
		if err := s.db.First(&user, "username = ?", username).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = models.ErrUserNotFound
			}

			JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %v", err), 0)
			return
		}

		if user.Verified {
			JSONErrResponse(w, models.ErrVerified, 0)
			return
		}

		if err := s.doSendVerificationEmail(&user, r); err != nil {
			JSONErrResponse(w, err, 0)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.(*models.User)
	if username != models.SelfUser && username != user.Username {
		JSONErrResponse(w, models.ErrOtherVerification, 0)
		return
	}

	if err := s.db.Model(&user).Updates(&models.User{
		Verified:     true,
		TokenVersion: user.TokenVersion + 1,
	}).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiResetPassword(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	u := r.Context().Value(keyUser)
	if u == nil {
		var user models.User
		if err := s.db.First(&user, "username = ?", username).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = models.ErrUserNotFound
			}

			JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %v", err), 0)
			return
		}

		if !user.Verified {
			JSONErrResponse(w, models.ErrUnverified, 0)
			return
		}

		t, err := user.GenerateEmailToken(s.config.JWT.Key, s.config.JWT.Issuer, models.AudPasswordReset,
			s.config.JWT.EmailValidity)
		if err != nil {
			JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
			return
		}

		tpl := EmailResetPasswordAPI
		if HTTPRequestAccepts(r, "text/html") {
			tpl = EmailResetPasswordUI
		}
		if err := s.SendEmail(tpl, EmailResetPasswordSubject, EmailUserInfo{&user, t}); err != nil {
			JSONErrResponse(w, fmt.Errorf("failed to send email: %w", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.(*models.User)
	if username != models.SelfUser && username != user.Username {
		JSONErrResponse(w, models.ErrOtherReset, 0)
		return
	}

	var req passwordReq
	if err := ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if req.Password == "" {
		JSONErrResponse(w, models.ErrPasswordRequired, 0)
		return
	}

	if err := s.db.Model(&user).Updates(&models.User{
		Password:     req.Password,
		TokenVersion: user.TokenVersion + 1,
	}).Error; err != nil {
		JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
