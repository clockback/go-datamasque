package datamasque_test

import (
	"context"
	"encoding/json"
	"github.com/clockback/go-datamasque"
	"net/http"
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
