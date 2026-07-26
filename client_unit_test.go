package datamasque

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// This code path cannot be tested indirectly due to all exported methods sending structured data.
func Test_sendRequestFailEncodeBody(t *testing.T) {
	clientConfig := ClientConfig{
		BaseURL: "",
		Timeout: 60 * time.Second,
	}
	client, err := New(&clientConfig)
	if err != nil {
		t.Fatal("Failed to create client.")
	}
	credentials := LoginObject{}

	_, err = sendRequest[any](
		client,
		context.TODO(),
		&credentials,
		http.MethodPost,
		"/",
		func() {}, // Invalid body
		http.StatusOK,
	)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := "failed to encode request body: json: unsupported type: func()"
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}
