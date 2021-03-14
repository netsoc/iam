package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gabriel-vasile/mimetype"
	log "github.com/sirupsen/logrus"

	"github.com/netsoc/iam/pkg/models"
)

var (
	acceptHeaderRegex = regexp.MustCompile(`([^()<>@,;:\\"\/[\]?={} \t]+)\/([^()<>@,;:\\"\/[\]?={} \t]+)`)
)

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

// HTTPRequestAccepts returns true if the given request accepts the provided MIME type
func HTTPRequestAccepts(r *http.Request, mime string) bool {
	m := acceptHeaderRegex.FindAllStringSubmatch(r.Header.Get("Accept"), -1)
	if len(m) == 0 {
		return false
	}

	mimes := make([]string, len(m))
	for i, subMatches := range m {
		mimes[i] = subMatches[0]
	}

	return mimetype.EqualsAny(mime, mimes...)
}
