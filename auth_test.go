package datamasque_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/clockback/go-datamasque"
	"github.com/go-playground/validator/v10"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestLoginSuccess(t *testing.T) {
	_, _, credentials := login(t)

	if credentials.Key != "abcdef1234567890abcdef1234567890abcdef12" {
		t.Fatalf("Incorrect key obtained: %q.", credentials.Key)
	}
}

func TestLoginFailRequestValidationFail(t *testing.T) {
	clientConfig := datamasque.ClientConfig{
		BaseURL: "invalid-url",
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		t.Fatalf("Expected error *validator.ValidationErrors, got %T: %v", err, err.Error())
	}

	expectedError := "failed validation on request body: Key: 'loginRequestPayload.Username' Error:Field validation for 'Username' failed on the 'required' tag"
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginRequestCreationFail(t *testing.T) {
	clientConfig := datamasque.ClientConfig{
		BaseURL: "invalid-url",
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(nil, "elliot", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	expectedError := `failed to create request: net/http: nil Context`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginRequestSendingFail(t *testing.T) {
	clientConfig := datamasque.ClientConfig{
		BaseURL: "invalid-url",
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "elliot", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	var urlError *url.Error
	if !errors.As(err, &urlError) {
		t.Fatalf("Expected error *url.Error, got %T: %v", err, err.Error())
	}

	expectedError := `failed to send request: Post "invalid-url/api/auth/token/login/": unsupported protocol scheme ""`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginWrongContentType(t *testing.T) {
	rawJSON, _ := createLoginObject(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	}))
	defer server.Close()

	clientConfig := datamasque.ClientConfig{
		BaseURL: server.URL,
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "elliot", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	expectedError := `expected JSON response, got Content-Type: text/plain`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginBadRequest(t *testing.T) {
	rawJSON, _ := createLoginObject(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(rawJSON)
	}))
	defer server.Close()

	clientConfig := datamasque.ClientConfig{
		BaseURL: server.URL,
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "elliot", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	expectedError := `request failed with status 400 Bad Request (400)`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid request payload"))
	}))
	defer server.Close()

	clientConfig := datamasque.ClientConfig{
		BaseURL: server.URL,
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "elliot", "mypassword")
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed to decode response body: invalid character 'i' looking for beginning of value`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLoginFailResponseMissingFields(t *testing.T) {
	rawJSON, _ := createLoginObject(t)
	delete(rawJSON, "key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	}))
	defer server.Close()

	clientConfig := datamasque.ClientConfig{
		BaseURL: server.URL,
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	_, err = client.Login(context.TODO(), "elliot", "mypassword")
	if err == nil {
		t.Fatal("Unexpected login success.")
	}

	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		t.Fatalf("Expected error *validator.ValidationErrors, got %T: %v", err, err.Error())
	}

	expectedError := `failed validation on response body: Key: 'rawLoginObject.Key' Error:Field validation for 'Key' failed on the 'required' tag`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestLogoutSuccess(t *testing.T) {
	mux, client, credentials := login(t)

	mux.HandleFunc("/api/auth/token/logout/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.Logout(context.TODO(), credentials); err != nil {
		t.Fatalf("Error on attempted logout: %T: %v", err, err.Error())
	}
}

func TestLogoutRequestUnauthorized(t *testing.T) {
	mux, client, credentials := login(t)

	mux.HandleFunc("/api/auth/token/logout/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	err := client.Logout(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed to send request: session token has expired or is invalid`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}
