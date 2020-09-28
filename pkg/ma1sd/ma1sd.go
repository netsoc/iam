package ma1sd

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	"github.com/netsoc/iam/pkg/models"
	"github.com/netsoc/iam/pkg/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	mxidRegex = regexp.MustCompile(`^@(\S+):(\S+)$`)
)

// MA1SD exposes endpoints needed by MA1SD to provide authentication and
// directory for Matrix
type MA1SD struct {
	Domain string
	DB     *gorm.DB

	router *mux.Router
}

// NewMA1SD creates a MA1SD handler
func NewMA1SD(domain string, db *gorm.DB) *MA1SD {
	r := mux.NewRouter()

	m := &MA1SD{
		Domain: domain,
		DB:     db,

		router: r,
	}

	r.HandleFunc("/auth/login", m.apiAuth).Methods("POST")

	r.HandleFunc("/directory/user/search", m.apiDirectory).Methods("POST")

	return m
}

func (m *MA1SD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.router.ServeHTTP(w, r)
}

func displayName(u *models.User) string {
	return u.FirstName + " " + u.LastName
}

type id struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type threePid struct {
	Medium  string `json:"email"`
	Address string `json:"address"`
}
type profile struct {
	DisplayName string `json:"display_name,omitempty"`

	ThreePIDs []threePid `json:"threepids,omitempty"`
	Roles     []string   `json:"roles"`
}

type authRequest struct {
	Auth struct {
		MXID      string
		LocalPart string
		Domain    string
		Password  string
	}
}
type authStatus struct {
	Success bool `json:"success"`
}
type authReponse struct {
	Auth authStatus `json:"auth"`

	ID      id      `json:"id"`
	Profile profile `json:"profile"`
}

func (m *MA1SD) apiAuth(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	mxid := fmt.Sprintf("@%v:%v", req.Auth.LocalPart, req.Auth.Domain)
	if req.Auth.MXID != mxid || req.Auth.Domain != m.Domain {
		util.JSONResponse(w, authReponse{}, http.StatusBadRequest)
		return
	}

	var user models.User
	if err := m.DB.First(&user, "username = ?", req.Auth.LocalPart).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			util.JSONResponse(w, authReponse{}, http.StatusNotFound)
			return
		}

		util.JSONResponse(w, authReponse{}, http.StatusInternalServerError)
		return
	}

	if !user.Verified {
		util.JSONResponse(w, authReponse{}, http.StatusUnauthorized)
		return
	}

	if err := user.CheckPassword(req.Auth.Password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			util.JSONResponse(w, authReponse{}, http.StatusUnauthorized)
			return
		}

		util.JSONResponse(w, authReponse{}, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, authReponse{
		Auth: authStatus{Success: true},
		ID: id{
			Type:  "localpart",
			Value: user.Username,
		},
		Profile: profile{
			DisplayName: displayName(&user),
			ThreePIDs: []threePid{
				{
					Medium:  "email",
					Address: user.Email,
				},
			},
		},
	}, http.StatusOK)
}

type directoryRequest struct {
	By         string
	SearchTerm string `json:"search_term"`
}
type directoryResult struct {
	AvatarURL   string `json:"avatar_url,omitempty"`
	DisplayName string `json:"display_name"`
	UserID      string `json:"user_id"`
}
type directoryResponse struct {
	Limited bool              `json:"limited"`
	Results []directoryResult `json:"results"`
}

func (m *MA1SD) apiDirectory(w http.ResponseWriter, r *http.Request) {
	var req directoryRequest
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	var query string
	switch req.By {
	case "name":
		query = "LOWER(CONCAT(first_name, ' ', last_name)) LIKE ?"
	case "threepid":
		query = "email LIKE ?"
	default:
		util.JSONResponse(w, directoryResponse{}, http.StatusBadRequest)
		return
	}

	var users []models.User
	term := fmt.Sprintf("%%%v%%", strings.ToLower(strings.ReplaceAll(req.SearchTerm, "%", "")))
	if err := m.DB.Where(query, term).Find(&users).Error; err != nil {
		util.JSONResponse(w, directoryResponse{}, http.StatusInternalServerError)
		return
	}

	results := []directoryResult{}
	for _, u := range users {
		if !u.Verified {
			continue
		}

		results = append(results, directoryResult{
			DisplayName: displayName(&u),
			UserID:      u.Username,
		})
	}

	util.JSONResponse(w, directoryResponse{
		Limited: false,
		Results: results,
	}, http.StatusOK)
}

type identityLookupItem struct {
	Medium  string `json:"medium"`
	Address string `json:"address"`

	ID id `json:"id"`
}
type identityOneRequest struct {
	Lookup threePid `json:"lookup"`
}
type identityBulkRequest struct {
	Lookup []threePid `json:"lookup"`
}
type identityOneResponse struct {
	Lookup identityLookupItem `json:"lookup"`
}
type identityBulkResponse struct {
	Lookup []identityLookupItem `json:"lookup"`
}

func (m *MA1SD) apiIdentityOne(w http.ResponseWriter, r *http.Request) {
}
func (m *MA1SD) apiIdentityBulk(w http.ResponseWriter, r *http.Request) {
}

type profileRequest struct {
	MXID      string
	LocalPart string
	Domain    string
}
type profileResponse struct {
	Profile profile `json:"profile"`
}

func (m *MA1SD) apiProfile(w http.ResponseWriter, r *http.Request) {
}
