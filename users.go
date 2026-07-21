package datamasque

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type UserRole string

const (
	UserRoleAdmin                  UserRole = "admin"
	UserRoleMaskRunner             UserRole = "mask_runner"
	UserRoleMaskBuilder            UserRole = "mask_builder"
	UserRoleRulesetLibraryManagers UserRole = "ruleset_library_managers"
)

func (role *UserRole) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case "admin":
		*role = UserRoleAdmin
	case "mask_runner":
		*role = UserRoleMaskRunner
	case "mask_builder":
		*role = UserRoleMaskBuilder
	case "ruleset_library_managers":
		*role = UserRoleRulesetLibraryManagers
	default:
		return fmt.Errorf("invalid user role: %s", s)
	}
	return nil
}

type rawUser struct {
	Id                       *int        `json:"id" validate:"required"`
	Username                 *string     `json:"username" validate:"required,max=255"`
	Email                    *string     `json:"email" validate:"required,max=254"`
	DateJoined               *time.Time  `json:"date_joined" validate:"required"`
	HasTemporaryPassword     *bool       `json:"has_temporary_password" validate:"required"`
	IsActive                 *bool       `json:"is_active" validate:"required"`
	IsStaff                  *bool       `json:"is_staff" validate:"required"`
	IsSuperuser              *bool       `json:"is_superuser" validate:"required"`
	IsSSOUser                *bool       `json:"is_sso_user" validate:"required"`
	IsSubscribedToSDDUpdates *bool       `json:"is_subscribed_to_sdd_updates" validate:"required"`
	Roles                    *[]UserRole `json:"user_roles" validate:"required"`
	Permissions              *[]string   `json:"user_permissions" validate:"required"`
}

type User struct {
	Id                       int        `json:"id"`
	Username                 string     `json:"username"`
	Email                    string     `json:"email"`
	DateJoined               time.Time  `json:"date_joined"`
	HasTemporaryPassword     bool       `json:"has_temporary_password"`
	IsActive                 bool       `json:"is_active"`
	IsStaff                  bool       `json:"is_staff"`
	IsSuperuser              bool       `json:"is_superuser"`
	IsSSOUser                bool       `json:"is_sso_user"`
	IsSubscribedToSDDUpdates bool       `json:"is_subscribed_to_sdd_updates"`
	Roles                    []UserRole `json:"user_roles"`
	Permissions              []string   `json:"user_permissions"`
}

func (r *rawUser) toUser() User {
	return User{
		Id:                       *r.Id,
		Username:                 *r.Username,
		Email:                    *r.Email,
		DateJoined:               *r.DateJoined,
		HasTemporaryPassword:     *r.HasTemporaryPassword,
		IsActive:                 *r.IsActive,
		IsStaff:                  *r.IsStaff,
		IsSuperuser:              *r.IsSuperuser,
		IsSSOUser:                *r.IsSSOUser,
		IsSubscribedToSDDUpdates: *r.IsSubscribedToSDDUpdates,
		Roles:                    *r.Roles,
		Permissions:              *r.Permissions,
	}
}

func (client *Client) ListUsers(ctx context.Context, credentials *LoginObject) ([]User, error) {
	fullURL := client.BaseURL.JoinPath("api", "users/").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.doAuthenticated(credentials, req)
	if err != nil {
		return nil, fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Listing users failed with status %s (%d)", resp.Status, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("Expected JSON response, got Content-Type: %s", contentType)
	}

	var usersData []rawUser
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&usersData)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode response body: %w", err)
	}

	for i := range usersData {
		err = client.validate.Struct(&usersData[i])
		if err != nil {
			return nil, fmt.Errorf("Failed validation on response body: %w", err)
		}
	}

	users := make([]User, len(usersData))
	for i, rawUser := range usersData {
		users[i] = rawUser.toUser()
	}

	return users, nil
}
