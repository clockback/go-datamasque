package datamasque_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/clockback/go-datamasque"
	"net/http"
	"slices"
	"strings"
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

func checkBoolValues(
	errors []string,
	received bool,
	expected bool,
	receivedUsername string,
	expectedUsername string,
	fieldName string,
	description string,
) []string {
	if received && !expected {
		return append(errors, fmt.Sprintf("Expected user %q not %s.", receivedUsername, description))
	} else if !received && expected {
		return append(errors, fmt.Sprintf("Expected user %q %s.", receivedUsername, description))
	}
	return errors
}

func validateUserEqual(received *datamasque.User, expected *datamasque.User) []string {
	errors := []string{}

	if received == nil {
		errors = append(errors, "Received user has nil pointer.")
	}
	if expected == nil {
		errors = append(errors, "Expected user has nil pointer.")
	}
	if len(errors) > 0 {
		return errors
	}

	if received.Id != expected.Id {
		err := fmt.Sprintf("Expected user to have ID %d, but had ID %d.", expected.Id, received.Id)
		errors = append(errors, err)
	}

	username := received.Username

	if username != expected.Username {
		err := fmt.Sprintf(
			"Expected user with ID %d to have name %v, but had %v.",
			received.Id,
			expected.Username,
			username,
		)
		errors = append(errors, err)
	}

	if received.Email != expected.Email {
		err := fmt.Sprintf(
			"Expected user %q to have email %v, but had %v.",
			username,
			expected.Email,
			received.Email,
		)
		errors = append(errors, err)
	}

	if received.DateJoined != expected.DateJoined {
		err := fmt.Sprintf(
			"Expected date joined of user %q to be %v, but had %v.",
			username,
			expected.DateJoined,
			received.DateJoined,
		)
		errors = append(errors, err)
	}

	if received.APIToken == nil && expected.APIToken != nil {
		err := fmt.Sprintf("Expected user %q to have API token %v, but had none.", username, *expected.APIToken)
		errors = append(errors, err)
	} else if received.APIToken != nil && expected.APIToken == nil {
		err := fmt.Sprintf("Expected user %q to have API no token, but had %v.", username, *received.APIToken)
		errors = append(errors, err)
	} else if received.APIToken != nil && *received.APIToken != *expected.APIToken {
		err := fmt.Sprintf(
			"Expected user %q to have API token %v, but had %v.",
			username,
			*expected.APIToken,
			*received.APIToken,
		)
		errors = append(errors, err)
	}

	errors = checkBoolValues(
		errors,
		received.HasTemporaryPassword,
		expected.HasTemporaryPassword,
		username,
		expected.Username,
		"HasTemporaryPassword",
		"have temporary password",
	)
	errors = checkBoolValues(
		errors,
		received.IsActive,
		expected.IsActive,
		username,
		expected.Username,
		"IsActive",
		"be active",
	)
	errors = checkBoolValues(
		errors,
		received.IsStaff,
		expected.IsStaff,
		username,
		expected.Username,
		"IsStaff",
		"be staff",
	)
	errors = checkBoolValues(
		errors,
		received.IsSuperuser,
		expected.IsSuperuser,
		username,
		expected.Username,
		"IsSuperuser",
		"be a superuser",
	)
	errors = checkBoolValues(
		errors,
		received.IsSSOUser,
		expected.IsSSOUser,
		username,
		expected.Username,
		"IsSSOUser",
		"be an SSO user",
	)
	errors = checkBoolValues(
		errors,
		received.IsSubscribedToSDDUpdates,
		expected.IsSubscribedToSDDUpdates,
		username,
		expected.Username,
		"IsSubscribedToSDDUpdates",
		"be subscribed to SDD updates",
	)

	if !slices.Equal(received.Roles, expected.Roles) {
		err := fmt.Sprintf(
			"Expected user %q to have roles %v, but had %v.",
			username,
			expected.Roles,
			received.Roles,
		)
		errors = append(errors, err)
	}

	if !slices.Equal(received.Permissions, expected.Permissions) {
		err := fmt.Sprintf(
			"Expected user %q to have permissions %v, but had %v.",
			username,
			expected.Permissions,
			received.Permissions,
		)
		errors = append(errors, err)
	}

	return errors
}

func assertUserEqual(t *testing.T, received *datamasque.User, expected *datamasque.User) {
	errors := validateUserEqual(received, expected)
	if len(errors) == 0 {
		return
	}

	t.Fatalf("Validation error comparing users:\n%s", strings.Join(errors, "\n"))
}

func TestListUsersSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, user := createUser(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]any{rawJSON})
	})

	users, err := client.ListUsers(context.TODO(), credentials)
	if err != nil {
		t.Fatalf("Error on attempt to list users: %v", err.Error())
	}

	if noUsers := len(users); noUsers != 1 {
		t.Fatalf("Incorrect number of users returned. Expected 1, got %d", noUsers)
	}

	assertUserEqual(t, &user, &users[0])
}

func TestCreateUserSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, returnUser := createUser(t)

	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rawJSON)
	})

	user := datamasque.CreateUserRequestPayload{
		Username: "bob",
		Password: "mypassword",
		Email:    "bob@mycompany.com",
		Roles:    []datamasque.UserRole{datamasque.UserRoleAdmin},
	}

	newUser, err := client.CreateUser(context.TODO(), credentials, &user)
	if err != nil {
		t.Fatalf("Error on attempt to create user: %v", err.Error())
	}

	assertUserEqual(t, &newUser, &returnUser)
}

func TestCreateUserNoRoles(t *testing.T) {
	_, client, credentials := login(t)

	user := datamasque.CreateUserRequestPayload{
		Username: "bob",
		Password: "mypassword",
		Email:    "bob@mycompany.com",
		Roles:    []datamasque.UserRole{},
	}

	_, err := client.CreateUser(context.TODO(), credentials, &user)
	if err == nil {
		t.Fatal("Unexpected user creation success.")
	}

	expectedError := "cannot create user with zero roles"
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestGetMyUserSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, returnUser := createUser(t)
	rawJSON["api_token"] = "abc"
	returnUser.APIToken = Ptr("abc")

	mux.HandleFunc("/api/users/me/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	})

	myUser, err := client.GetMyUser(context.TODO(), credentials)
	if err != nil {
		t.Fatalf("Error on attempt to get authenticated user: %v", err.Error())
	}

	assertUserEqual(t, &myUser, &returnUser)
}

func TestGetUserByIDSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, returnUser := createUser(t)

	mux.HandleFunc("/api/users/123/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	})

	myUser, err := client.GetUserByID(context.TODO(), credentials, 123)
	if err != nil {
		t.Fatalf("Error on attempt to get user with ID 123: %v", err.Error())
	}

	assertUserEqual(t, &myUser, &returnUser)
}
