package datamasque_test

import (
	"bytes"
	"crypto/x509"
	"github.com/clockback/go-datamasque"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewSuccess(t *testing.T) {
	var logBuffer bytes.Buffer
	handler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	logger := slog.New(handler)

	timeout := 5 * time.Second
	clientConfig := datamasque.ClientConfig{
		BaseURL: "https://my-server.com",
		Timeout: timeout,
		Logger:  logger,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	logOutput := logBuffer.String()
	expectedMessage := "InsecureSkipVerify enabled, nullifying provided RootCAs"
	if strings.Contains(logOutput, expectedMessage) {
		t.Fatalf("Log contains message: %s", expectedMessage)
	}

	if client.HTTPClient.Timeout != timeout {
		t.Fatalf("Expected timeout %v, got %v", timeout, client.HTTPClient.Timeout)
	}
}

func TestNewSuccessWithRootCAs(t *testing.T) {
	var logBuffer bytes.Buffer
	handler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	logger := slog.New(handler)

	timeout := 5 * time.Second
	clientConfig := datamasque.ClientConfig{
		BaseURL: "https://my-server.com",
		Timeout: timeout,
		RootCAs: &x509.CertPool{},
		Logger:  logger,
	}

	client, err := datamasque.New(&clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	logOutput := logBuffer.String()
	expectedMessage := "InsecureSkipVerify enabled, nullifying provided RootCAs"
	if strings.Contains(logOutput, expectedMessage) {
		t.Fatalf("Log contains message: %s", expectedMessage)
	}

	if client.HTTPClient.Timeout != timeout {
		t.Fatalf("Expected timeout %v, got %v", timeout, client.HTTPClient.Timeout)
	}

	transport, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected *http.Transport type.")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("Failed to assign root certificate authorities.")
	}
}

func TestNewInvalidURL(t *testing.T) {
	clientConfig := datamasque.ClientConfig{
		BaseURL: "https://\n.com",
	}

	_, err := datamasque.New(&clientConfig)
	if err == nil {
		t.Fatal("Expected error on logout.")
	}

	expectedError := `failed to parse URL: parse "https://\n.com": net/url: invalid control character in URL`
	if err.Error() != expectedError {
		t.Fatalf("Expected %q, got %q.", expectedError, err.Error())
	}
}

func TestNewTLSWarning(t *testing.T) {
	var logBuffer bytes.Buffer
	handler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	logger := slog.New(handler)

	clientConfig := datamasque.ClientConfig{
		BaseURL:            "https://my-server.com",
		InsecureSkipVerify: true,
		RootCAs:            &x509.CertPool{},
		Logger:             logger,
	}

	if _, err := datamasque.New(&clientConfig); err != nil {
		t.Fatalf("Failed to create client due to %T: %v", err, err.Error())
	}

	logOutput := logBuffer.String()
	expectedMessage := "InsecureSkipVerify enabled, nullifying provided RootCAs"
	if !strings.Contains(logOutput, expectedMessage) {
		t.Fatalf("Logs missing message: %s", expectedMessage)
	}
}
