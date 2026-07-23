package datamasque

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

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

func (client *Client) Login(ctx context.Context, username string, password string) (*LoginObject, error) {
	payload := loginRequestPayload{
		Username: username,
		Password: password,
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

	if err = client.validate.Struct(rawData); err != nil {
		return nil, fmt.Errorf("Failed validation on response body: %w", err)
	}

	tokenData := rawData.toLoginObject()
	return &tokenData, nil
}

func (client *Client) Logout(ctx context.Context, credentials *LoginObject) error {
	return client.sendRequestStatusNoContent(ctx, credentials, http.MethodPost, "/api/auth/token/logout/", nil)
}
