package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/netsoc/iam/pkg/email"
	"github.com/netsoc/iam/pkg/models"
	"github.com/netsoc/iam/pkg/util"
)

func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	util.JSONErrResponse(w, errors.New("API endpoint not found"), http.StatusNotFound)
}
func (s *Server) apiMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	util.JSONErrResponse(w, errors.New("method not allowed on API endpoint"), http.StatusMethodNotAllowed)
}

func (s *Server) apiOneUser(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(keyUser).(*models.User)
	claims := r.Context().Value(keyClaims).(*models.UserClaims)

	username := mux.Vars(r)["username"]
	// Only admins can access other users
	if (username != models.SelfUser && username != actor.Username) && !actor.ValidAdmin(claims) {
		util.JSONErrResponse(w, models.ErrAdminRequired, 0)
		return
	}

	var user, patch models.User
	if r.Method == http.MethodPatch {
		if err := util.ParseJSONBody(&patch, w, r); err != nil {
			return
		}

		if !actor.ValidAdmin(claims) {
			if err := patch.NonAdminSaveOK(s.config.ReservedUsernames); err != nil {
				util.JSONErrResponse(w, err, 0)
				return
			}
		}
	}

	do := func() error {
		if username == models.SelfUser {
			user = *actor
		} else if err := s.db.First(&user, "username = ?", username).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = models.ErrUserNotFound
			}

			return fmt.Errorf("failed to fetch user from database: %w", err)
		}

		switch r.Method {
		case http.MethodDelete:
			t := s.db
			if !s.config.PostgreSQL.SoftDelete {
				t = s.db.Unscoped()
			}

			if err := t.Delete(&user).Error; err != nil {
				return fmt.Errorf("failed to write to database: %w", err)
			}
		case http.MethodPatch:
			// Copy the user (so we can return the old one)
			updated := user
			if err := s.db.Model(&updated).Updates(patch).Error; err != nil {
				return fmt.Errorf("failed to write to database: %w", err)
			}
		default:
		}

		return nil
	}
	if err := do(); err != nil {
		util.JSONErrResponse(w, err, 0)
		return
	}

	user.Clean()
	util.JSONResponse(w, user, http.StatusOK)
}

func (s *Server) apiGetUsers(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	if err := s.db.Omit("password").Find(&users).Error; err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to fetch users from database: %w", err), 0)
		return
	}

	util.JSONResponse(w, users, http.StatusOK)
}

func (s *Server) apiGetUserByID(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := s.db.Omit("password").First(&user, mux.Vars(r)["uid"]).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = models.ErrUserNotFound
		}

		util.JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %w", err), 0)
		return
	}

	util.JSONResponse(w, user, http.StatusOK)
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := util.ParseJSONBody(&user, w, r); err != nil {
		return
	}

	if r.Context().Value(keyUser) == nil {
		if err := user.NonAdminSaveOK(s.config.ReservedUsernames); err != nil {
			util.JSONErrResponse(w, err, 0)
			return
		}
	}

	if err := s.db.Create(&user).Error; err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	if err := s.doSendVerificationEmail(&user, r); err != nil {
		util.JSONErrResponse(w, err, 0)
		return
	}

	user.Clean()
	util.JSONResponse(w, user, http.StatusCreated)
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

		util.JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %w", err), 0)
		return
	}

	if !*user.Verified {
		util.JSONErrResponse(w, models.ErrUnverified, 0)
		return
	}

	var req passwordReq
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			util.JSONErrResponse(w, models.ErrIncorrectPassword, 0)
			return
		}

		util.JSONErrResponse(w, err, 0)
		return
	}

	t, err := user.GenerateToken(s.config.JWT.Key, s.config.JWT.Issuer, user.Renewed.Add(s.config.JWT.LoginValidity))
	if err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
		return
	}

	util.JSONResponse(w, tokenRes{t}, http.StatusOK)
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(keyUser).(*models.User)
	claims := r.Context().Value(keyClaims).(*models.UserClaims)

	username := mux.Vars(r)["username"]
	if username != models.SelfUser {
		// Only admins can logout other users
		if username != actor.Username && !actor.ValidAdmin(claims) {
			util.JSONErrResponse(w, models.ErrAdminRequired, 0)
			return
		}
	} else {
		username = actor.Username
	}

	result := s.db.
		Model(&models.User{}).
		Where("username = ?", username).
		UpdateColumn("token_version", gorm.Expr("token_version + ?", 1))
	if result.Error != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", result.Error), 0)
		return
	}
	if result.RowsAffected == 0 {
		util.JSONErrResponse(w, models.ErrUserNotFound, 0)
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
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}
	duration, err := time.ParseDuration(req.Duration)
	if err != nil {
		util.JSONErrResponse(w, errors.New("failed to parse duration"), http.StatusBadRequest)
		return
	}

	var user models.User
	if err := s.db.First(&user, "username = ?", mux.Vars(r)["username"]).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = models.ErrUserNotFound
		}

		util.JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %w", err), 0)
		return
	}

	t, err := user.GenerateToken(s.config.JWT.Key, s.config.JWT.Issuer, time.Now().Add(duration))
	if err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
		return
	}

	util.JSONResponse(w, tokenRes{t}, http.StatusOK)
}

func (s *Server) doSendVerificationEmail(user *models.User, r *http.Request) error {
	t, err := user.GenerateEmailToken(s.config.JWT.Key, s.config.JWT.Issuer, models.AudVerification,
		s.config.JWT.EmailValidity)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	tpl := email.VerificationAPI
	if util.HTTPRequestAccepts(r, "text/html") {
		tpl = email.VerificationUI
	}
	if err := s.email.SendEmail(tpl, email.VerificationSubject, email.UserInfo{User: user, Token: t}); err != nil {
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

			util.JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %w", err), 0)
			return
		}

		if *user.Verified {
			util.JSONErrResponse(w, models.ErrVerified, 0)
			return
		}

		if err := s.doSendVerificationEmail(&user, r); err != nil {
			util.JSONErrResponse(w, err, 0)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.(*models.User)
	if username != models.SelfUser && username != user.Username {
		util.JSONErrResponse(w, models.ErrOtherVerification, 0)
		return
	}

	t := true
	if err := s.db.Model(&user).Updates(models.User{Verified: &t}).Error; err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
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

			util.JSONErrResponse(w, fmt.Errorf("failed to fetch user from database: %w", err), 0)
			return
		}

		if !*user.Verified {
			util.JSONErrResponse(w, models.ErrUnverified, 0)
			return
		}

		t, err := user.GenerateEmailToken(s.config.JWT.Key, s.config.JWT.Issuer, models.AudPasswordReset,
			s.config.JWT.EmailValidity)
		if err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to generate token: %w", err), 0)
			return
		}

		tpl := email.ResetPasswordAPI
		if util.HTTPRequestAccepts(r, "text/html") {
			tpl = email.ResetPasswordUI
		}
		if err := s.email.SendEmail(tpl, email.ResetPasswordSubject, email.UserInfo{User: &user, Token: t}); err != nil {
			util.JSONErrResponse(w, fmt.Errorf("failed to send email: %w", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.(*models.User)
	if username != models.SelfUser && username != user.Username {
		util.JSONErrResponse(w, models.ErrOtherReset, 0)
		return
	}

	var req passwordReq
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if req.Password == "" {
		util.JSONErrResponse(w, models.ErrPasswordRequired, 0)
		return
	}

	if err := s.db.Model(&user).Updates(models.User{
		Password: &req.Password,
	}).Error; err != nil {
		util.JSONErrResponse(w, fmt.Errorf("failed to write to database: %w", err), 0)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
