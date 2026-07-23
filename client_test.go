package datamasque_test

import (
	"bytes"
	"crypto/x509"
	"github.com/clockback/go-datamasque"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNewTLSWarning(t *testing.T) {
	var logBuffer bytes.Buffer
	handler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})
	logger := slog.New(handler)

	clientConfig := datamasque.ClientConfig{
		BaseURL:            "https://my-server.com",
		Timeout:            60 * time.Second,
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
		t.Errorf("Logs missing message: %s", expectedMessage)
	}
}
