package datamasque_test

import (
	"context"
	"encoding/json"
	"github.com/clockback/go-datamasque"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Ptr[T any](v T) *T {
	return &v
}

func createLoginObject(t *testing.T) (map[string]any, datamasque.LoginObject) {
	rawJSON := map[string]any{
		"id":                1,
		"key":               "abcdef1234567890abcdef1234567890abcdef12",
		"client_ip":         "255.255.255.255",
		"client_browser":    "MyBrowser",
		"client_os":         "MyOS 2020",
		"client_device":     "MyDevice",
		"date_time_created": "2024-01-01T12:23:45.947293Z",
		"date_time_expires": "2024-01-01T20:23:45.947293Z",
	}

	dateTimeCreated, err := time.Parse(time.RFC3339Nano, "2024-01-01T12:23:45.947293Z")
	if err != nil {
		t.Fatal("Could not parse time.")
	}

	dateTimeExpires, err := time.Parse(time.RFC3339Nano, "2024-01-01T20:23:45.947293Z")
	if err != nil {
		t.Fatal("Could not parse time.")
	}

	loginObject := datamasque.LoginObject{
		Id:              1,
		Key:             "abcdef1234567890abcdef1234567890abcdef12",
		ClientIP:        Ptr("255.255.255.255"),
		ClientBrowser:   Ptr("MyBrowser"),
		ClientOS:        Ptr("MyOS 2020"),
		ClientDevice:    Ptr("MyDevice"),
		DateTimeCreated: Ptr(dateTimeCreated),
		DateTimeExpires: Ptr(dateTimeExpires),
	}
	return rawJSON, loginObject
}

func testServer(t *testing.T) (*http.ServeMux, *httptest.Server) {
	rawJSON, _ := createLoginObject(t)
	mux := http.NewServeMux()

	mux.HandleFunc("/api/auth/token/login/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rawJSON)
	})

	server := httptest.NewServer(mux)

	t.Cleanup(server.Close)

	return mux, server
}

func login(t *testing.T) (*http.ServeMux, *datamasque.Client, *datamasque.LoginObject) {
	mux, server := testServer(t)

	clientConfig := datamasque.ClientConfig{
		BaseURL: server.URL,
		Timeout: 60 * time.Second,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	credentials, err := client.Login(context.TODO(), "elliot", "mypassword")
	if err != nil {
		t.Fatalf("Unable to log in due to %T: %v", err, err.Error())
	}

	return mux, client, credentials
}
