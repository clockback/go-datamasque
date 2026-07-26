package datamasque_test

import (
	"context"
	"encoding/json"
	"github.com/clockback/go-datamasque"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func createUser(t *testing.T) (map[string]any, datamasque.User) {
	rawJSON := map[string]any{
		"id":                           1,
		"username":                     "bob",
		"email":                        "bob@mycompany.com",
		"date_joined":                  "2024-01-01T12:23:45.947293Z",
		"api_token":                    "",
		"has_temporary_password":       true,
		"is_active":                    true,
		"is_staff":                     true,
		"is_superuser":                 true,
		"is_sso_user":                  true,
		"is_subscribed_to_sdd_updates": false,
		"user_roles":                   []string{"admin"},
		"user_permissions":             []string{},
	}

	dateJoined, err := time.Parse(time.RFC3339Nano, "2024-01-01T12:23:45.947293Z")
	if err != nil {
		t.Fatal("Could not parse time.")
	}
	user := datamasque.User{
		Id:                       1,
		Username:                 "bob",
		Email:                    "bob@mycompany.com",
		DateJoined:               dateJoined,
		HasTemporaryPassword:     true,
		IsActive:                 true,
		IsStaff:                  true,
		IsSuperuser:              true,
		IsSSOUser:                true,
		IsSubscribedToSDDUpdates: false,
		Roles:                    []datamasque.UserRole{"admin"},
		Permissions:              []string{},
	}

	return rawJSON, user
}

func TestListUsersSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, _ := createUser(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]any{rawJSON})
	})

	_, err := client.ListUsers(context.TODO(), credentials)
	if err != nil {
		t.Fatalf("Error on attempt to list users: %v", err.Error())
	}
}

func TestListUsersRequestCreationFail(t *testing.T) {
	_, client, credentials := login(t)

	_, err := client.ListUsers(nil, credentials)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed to create request: net/http: nil Context`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestListUsersRequestSendingFail(t *testing.T) {
	_, client, credentials := login(t)

	url, _ := url.Parse("invalid-url")
	client.BaseURL = url

	_, err := client.ListUsers(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on listing users.")
	}

	expectedError := `failed to send request: Get "invalid-url/api/users/": unsupported protocol scheme ""`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestListUsersRequestUnauthorized(t *testing.T) {
	mux, client, credentials := login(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := client.ListUsers(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on list users.")
	}

	expectedError := `failed to send request: session token has expired or is invalid`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestListUsersRequestBadRequest(t *testing.T) {
	mux, client, credentials := login(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	_, err := client.ListUsers(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `request failed with status 400 Bad Request (400)`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestListUsersMalformedJSON(t *testing.T) {
	mux, client, credentials := login(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid request payload"))
	})

	_, err := client.ListUsers(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed to decode response body: invalid character 'i' looking for beginning of value`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestListUsersFailValidation(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, _ := createUser(t)
	rawJSON["id"] = nil

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]any{rawJSON})
	})

	_, err := client.ListUsers(context.TODO(), credentials)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed validation on response body: Key: 'rawUser.Id' Error:Field validation for 'Id' failed on the 'required' tag`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}
