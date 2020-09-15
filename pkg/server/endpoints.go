package server

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/netsoc/iam/pkg/models"
	"gorm.io/gorm"
)

func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	JSONErrResponse(w, errors.New("API endpoint not found"), http.StatusNotFound)
}
func (s *Server) apiMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	JSONErrResponse(w, errors.New("method not allowed on API endpoint"), http.StatusNotFound)
}

func (s *Server) apiOneUser(w http.ResponseWriter, r *http.Request) {
	var user, patch models.User

	if r.Method == http.MethodPatch {
		if err := ParseJSONBody(&patch, w, r); err != nil {
			return
		}
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("password").First(&user, "username = ?", mux.Vars(r)["username"]).Error; err != nil {
			return err
		}

		switch r.Method {
		case http.MethodDelete:
			t := tx
			if !s.config.DB.SoftDelete {
				t = tx.Unscoped()
			}

			return t.Delete(&user).Error
		case http.MethodPatch:
			if err := tx.Model(&user).Updates(&patch).Error; err != nil {
				return err
			}
			user.Password = ""
		default:
		}

		return nil
	}); err != nil {
		JSONErrResponse(w, err, 0)
		return
	}

	JSONResponse(w, user, http.StatusOK)
}

func (s *Server) apiGetUsers(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	if err := s.db.Omit("password").Find(&users).Error; err != nil {
		JSONErrResponse(w, err, 0)
		return
	}

	JSONResponse(w, users, http.StatusOK)
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := ParseJSONBody(&user, w, r); err != nil {
		return
	}

	if err := s.db.Create(&user).Error; err != nil {
		JSONErrResponse(w, err, 0)
		return
	}

	user.Password = ""
	JSONResponse(w, user, http.StatusCreated)
}
