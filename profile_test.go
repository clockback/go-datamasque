package datamasque_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/clockback/go-datamasque"
	"net/http"
	"strings"
	"testing"
)

func createProfile(t *testing.T) (map[string]any, datamasque.Profile) {
	rawJSON := map[string]any{
		"git_directory_path": "my/path",
	}
	user := datamasque.Profile{
		GitDirectoryPath: Ptr("my/path"),
	}
	return rawJSON, user
}

func validateProfileEqual(received *datamasque.Profile, expected *datamasque.Profile) []string {
	errors := []string{}

	if received == nil {
		errors = append(errors, "Received profile has nil pointer.")
	}
	if expected == nil {
		errors = append(errors, "Expected profile has nil pointer.")
	}
	if len(errors) > 0 {
		return errors
	}

	if *received.GitDirectoryPath != *expected.GitDirectoryPath {
		err := fmt.Sprintf(
			"Expected profile to have Git directory path %v, but had Git directory path %v.",
			*expected.GitDirectoryPath,
			*received.GitDirectoryPath,
		)
		errors = append(errors, err)
	}

	return errors
}

func assertProfileEqual(t *testing.T, received *datamasque.Profile, expected *datamasque.Profile) {
	errors := validateProfileEqual(received, expected)
	if len(errors) == 0 {
		return
	}

	t.Fatalf("Validation error comparing profiles:\n%s", strings.Join(errors, "\n"))
}

func TestGetMyProfileSuccess(t *testing.T) {
	mux, client, credentials := login(t)
	rawJSON, returnProfile := createProfile(t)

	mux.HandleFunc("/api/users/me/profile/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	})

	myProfile, err := client.GetMyProfile(context.TODO(), credentials)
	if err != nil {
		t.Fatalf("Error on attempt to get authenticated user's profile: %v", err.Error())
	}

	assertProfileEqual(t, &myProfile, &returnProfile)
}
