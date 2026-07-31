package main

import (
	"encoding/json"
	"net/http"
)

// tenableError is the error envelope documented across Tenable VM endpoints.
// Examples consistently use a string "error" name even though some OpenAPI
// schemas incorrectly type it as integer.
// Doc URL: https://developer.tenable.com/reference/users-list
type tenableError struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, name, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(tenableError{
		StatusCode: status,
		Error:      name,
		Message:    message,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
