package datamasque

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClientConfig struct {
	BaseURL            string
	Timeout            time.Duration
	InsecureSkipVerify bool
	RootCAs            *x509.CertPool
	Logger             *slog.Logger
}

type Client struct {
	BaseURL    *url.URL
	HTTPClient *http.Client

	validate *validator.Validate
	logger   *slog.Logger
}

type rawLoginObject struct {
	Id              *int       `json:"id" validate:"required"`
	Key             *string    `json:"key" validate:"required"`
	ClientIP        *string    `json:"client_ip" validate:"omitempty,ip"`
	ClientBrowser   *string    `json:"client_browser"`
	ClientOS        *string    `json:"client_os"`
	ClientDevice    *string    `json:"client_device"`
	DateTimeCreated *time.Time `json:"date_time_created"`
	DateTimeExpires *time.Time `json:"date_time_expires"`
}

type LoginObject struct {
	Id              int        `json:"id"`
	Key             string     `json:"key"`
	ClientIP        *string    `json:"client_ip"`
	ClientBrowser   *string    `json:"client_browser"`
	ClientOS        *string    `json:"client_os"`
	ClientDevice    *string    `json:"client_device"`
	DateTimeCreated *time.Time `json:"date_time_created"`
	DateTimeExpires *time.Time `json:"date_time_expires"`
}

func (r *rawLoginObject) toLoginObject() LoginObject {
	return LoginObject{
		Id:              *r.Id,
		Key:             *r.Key,
		ClientIP:        r.ClientIP,
		ClientBrowser:   r.ClientBrowser,
		ClientOS:        r.ClientOS,
		ClientDevice:    r.ClientDevice,
		DateTimeCreated: r.DateTimeCreated,
		DateTimeExpires: r.DateTimeExpires,
	}
}

type loginRequestPayload struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func loggerOrDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}

func New(config *ClientConfig) (*Client, error) {
	parsedURL, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, err
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("Failed to assert default transport")
	}
	clonedTransport := transport.Clone()

	var TLSClientConfig *tls.Config
	if clonedTransport.TLSClientConfig == nil {
		TLSClientConfig = &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}
	} else {
		TLSClientConfig = clonedTransport.TLSClientConfig.Clone()
		TLSClientConfig.InsecureSkipVerify = config.InsecureSkipVerify
	}
	if config.RootCAs != nil {
		if config.InsecureSkipVerify {
			logger := loggerOrDefault(config.Logger)
			logger.Warn("InsecureSkipVerify enabled, nullifying provided RootCAs")
		}
		TLSClientConfig.RootCAs = config.RootCAs.Clone()
	}

	clonedTransport.TLSClientConfig = TLSClientConfig
	client := http.Client{
		Timeout:   config.Timeout,
		Transport: clonedTransport,
	}

	return &Client{
		BaseURL:    parsedURL,
		HTTPClient: &client,
		validate:   validator.New(),
		logger:     config.Logger,
	}, nil
}

func (client *Client) Login(ctx context.Context, username string, password string) (*LoginObject, error) {
	payload := loginRequestPayload{
		Username: username,
		Password: password,
	}

	if err := client.validate.Struct(payload); err != nil {
		return nil, fmt.Errorf("failed validation on request body: %w", err)
	}

	fullURL := client.BaseURL.JoinPath("api", "auth", "token", "login/").String()

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Login failed with status %s (%d)", resp.Status, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("Expected JSON response, got Content-Type: %s", contentType)
	}

	var rawData rawLoginObject
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&rawData)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode response body: %w", err)
	}

	err = client.validate.Struct(rawData)
	if err != nil {
		return nil, fmt.Errorf("Failed validation on response body: %w", err)
	}

	tokenData := rawData.toLoginObject()
	return &tokenData, nil
}

func (client *Client) doAuthenticated(credentials *LoginObject, req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Token "+credentials.Key)

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("Session token has expired or is invalid.")
	}

	return resp, nil
}

func (client *Client) Logout(ctx context.Context, credentials *LoginObject) error {
	fullURL := client.BaseURL.JoinPath("api", "auth", "token", "logout/").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, nil)
	if err != nil {
		return fmt.Errorf("Failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.doAuthenticated(credentials, req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Logout failed with status %s (%d)", resp.Status, resp.StatusCode)
	}

	return nil
}
