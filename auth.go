package datamasque

import (
	"context"
	"net/http"
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
	var tokenData LoginObject

	payload := loginRequestPayload{
		Username: username,
		Password: password,
	}
	path := "/api/auth/token/login/"
	rawData, err := sendRequest[rawLoginObject](client, ctx, nil, http.MethodPost, path, payload, http.StatusOK)
	if err != nil {
		return &tokenData, err
	}

	tokenData = rawData.toLoginObject()
	return &tokenData, nil
}

func (client *Client) Logout(ctx context.Context, credentials *LoginObject) error {
	return client.sendRequestStatusNoContent(ctx, credentials, http.MethodPost, "/api/auth/token/logout/", nil)
}
