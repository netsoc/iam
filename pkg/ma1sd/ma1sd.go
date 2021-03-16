package ma1sd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/netsoc/iam/pkg/models"
	"github.com/netsoc/iam/pkg/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func writeAccessLog(w io.Writer, params handlers.LogFormatterParams) {
	log.WithFields(log.Fields{
		"remote":  params.Request.RemoteAddr,
		"agent":   params.Request.UserAgent(),
		"status":  params.StatusCode,
		"resSize": params.Size,
	}).Debugf("ma1sd %v %v", params.Request.Method, params.URL.RequestURI())
}

// MA1SD exposes endpoints needed by MA1SD to provide authentication and
// directory for Matrix
type MA1SD struct {
	Domain   string
	Validity time.Duration
	DB       *gorm.DB

	handler http.Handler
}

// NewMA1SD creates a MA1SD handler
func NewMA1SD(domain string, validity time.Duration, db *gorm.DB) *MA1SD {
	r := mux.NewRouter()

	m := &MA1SD{
		Domain:   domain,
		Validity: validity,
		DB:       db,

		handler: handlers.CustomLoggingHandler(nil, r, writeAccessLog),
	}

	r.HandleFunc("/auth/login", m.apiAuth).Methods("POST")

	r.HandleFunc("/directory/user/search", m.apiDirectory).Methods("POST")

	r.HandleFunc("/identity/single", m.apiIdentityOne).Methods("POST")
	r.HandleFunc("/identity/bulk", m.apiIdentityBulk).Methods("POST")

	r.HandleFunc("/profile/displayName", m.apiProfile("DisplayName")).Methods("POST")
	r.HandleFunc("/profile/threepids", m.apiProfile("ThreePIDs")).Methods("POST")
	r.HandleFunc("/profile/roles", m.apiProfile("Roles")).Methods("POST")

	return m
}

func (m *MA1SD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.handler.ServeHTTP(w, r)
}

func mxid(local, domain string) string {
	return fmt.Sprintf("@%v:%v", local, domain)
}
func displayName(u *models.User) string {
	return u.FirstName + " " + u.LastName
}

type id struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type threePid struct {
	Medium  string `json:"medium"`
	Address string `json:"address"`
}

type Auth struct {
	MXID      string
	LocalPart string
	Domain    string
	Password  string
}
type authRequest struct {
	Auth Auth
}
type authProfile struct {
	DisplayName string     `json:"display_name,omitempty"`
	ThreePIDs   []threePid `json:"three_pids,omitempty"`
}
type authResult struct {
	Success bool `json:"success"`

	ID      id          `json:"id"`
	Profile authProfile `json:"profile"`
}
type authReponse struct {
	Auth authResult `json:"auth"`
}

func (m *MA1SD) apiAuth(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	if req.Auth.MXID != mxid(req.Auth.LocalPart, req.Auth.Domain) || req.Auth.Domain != m.Domain {
		util.JSONResponse(w, authReponse{}, http.StatusBadRequest)
		return
	}

	var user models.User
	if err := m.DB.First(&user, "LOWER(username) = ?", req.Auth.LocalPart).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			util.JSONResponse(w, authReponse{}, http.StatusNotFound)
			return
		}

		util.JSONResponse(w, authReponse{}, http.StatusInternalServerError)
		return
	}

	if !*user.Verified || time.Now().After(user.Renewed.Add(m.Validity)) {
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
		Auth: authResult{
			Success: true,
			ID: id{
				Type:  "localpart",
				Value: strings.ToLower(user.Username),
			},
			Profile: authProfile{
				DisplayName: displayName(&user),
				ThreePIDs: []threePid{
					{
						Medium:  "email",
						Address: user.Email,
					},
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

	query += " AND verified = true"

	var users []models.User
	term := fmt.Sprintf("%%%v%%", strings.ToLower(strings.ReplaceAll(req.SearchTerm, "%", "")))
	if err := m.DB.Where(query, term).Find(&users).Error; err != nil {
		util.JSONResponse(w, directoryResponse{}, http.StatusInternalServerError)
		return
	}

	results := make([]directoryResult, len(users))
	for i, u := range users {
		results[i] = directoryResult{
			DisplayName: displayName(&u),
			UserID:      strings.ToLower(u.Username),
		}
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
type identityOneResponse struct {
	Lookup identityLookupItem `json:"lookup,omitempty"`
}

func (m *MA1SD) identityLookup(lookup threePid) (identityLookupItem, error) {
	item := identityLookupItem{}
	if lookup.Medium != "email" {
		return item, errors.New("only email 3pid is supported")
	}

	var user models.User
	if err := m.DB.First(&user, "verified = true AND email = ?", lookup.Address).Error; err != nil {
		return item, err
	}

	return identityLookupItem{
		Medium:  "email",
		Address: user.Email,
		ID: id{
			Type:  "localpart",
			Value: strings.ToLower(user.Username),
		},
	}, nil
}

func (m *MA1SD) apiIdentityOne(w http.ResponseWriter, r *http.Request) {
	var req identityOneRequest
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	item, err := m.identityLookup(req.Lookup)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			util.JSONResponse(w, map[string]string{}, http.StatusNotFound)
			return
		}

		util.JSONResponse(w, identityOneResponse{}, http.StatusInternalServerError)
		return
	}

	util.JSONResponse(w, identityOneResponse{Lookup: item}, http.StatusOK)
}

type identityBulkRequest struct {
	Lookup []threePid `json:"lookup"`
}
type identityBulkResponse struct {
	Lookup []identityLookupItem `json:"lookup"`
}

func (m *MA1SD) apiIdentityBulk(w http.ResponseWriter, r *http.Request) {
	var req identityBulkRequest
	if err := util.ParseJSONBody(&req, w, r); err != nil {
		return
	}

	items := []identityLookupItem{}
	for _, l := range req.Lookup {
		item, err := m.identityLookup(l)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}

			util.JSONResponse(w, identityOneResponse{}, status)
			return
		}

		items = append(items, item)
	}

	util.JSONResponse(w, identityBulkResponse{Lookup: items}, http.StatusOK)
}

type profile struct {
	DisplayName string `json:"display_name,omitempty"`

	ThreePIDs []threePid `json:"threepids,omitempty"`
	Roles     []string   `json:"roles"`
}
type profileRequest struct {
	MXID      string
	LocalPart string
	Domain    string
}
type profileResponse struct {
	Profile map[string]interface{} `json:"profile"`
}

var emptyProfileResponse = map[string]struct{}{"profile": {}}

func (m *MA1SD) apiProfile(field string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req profileRequest
		if err := util.ParseJSONBody(&req, w, r); err != nil {
			return
		}

		if req.MXID != mxid(req.LocalPart, req.Domain) || req.Domain != m.Domain {
			util.JSONResponse(w, emptyProfileResponse, http.StatusBadRequest)
			return
		}

		var user models.User
		if err := m.DB.First(&user, "verified = true AND LOWER(username) = ?", req.LocalPart).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				util.JSONResponse(w, emptyProfileResponse, http.StatusOK)
				return
			}

			util.JSONResponse(w, emptyProfileResponse, http.StatusInternalServerError)
			return
		}

		p := map[string]interface{}{}
		switch field {
		case "DisplayName":
			p["display_name"] = displayName(&user)
		case "ThreePIDs":
			p["threepids"] = []threePid{
				{
					Medium:  "email",
					Address: user.Email,
				},
			}
		case "Roles":
			p["roles"] = []string{}
		default:
			panic(fmt.Sprintf("invalid profile field %v", field))
		}

		util.JSONResponse(w, profileResponse{Profile: p}, http.StatusOK)
	}
}
