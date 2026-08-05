package datamasque

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

type rawUserWithToken struct {
	rawUser

	APIToken *string `json:"api_token" validate:"required"`
}

type User struct {
	Id                       int        `json:"id"`
	Username                 string     `json:"username"`
	Email                    string     `json:"email"`
	DateJoined               time.Time  `json:"date_joined"`
	APIToken                 *string    `json:"api_token"`
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

func (r *rawUserWithToken) toUser() User {
	user := r.rawUser.toUser()
	user.APIToken = r.APIToken
	return user
}

type CreateUserRequestPayload struct {
	Username             string
	Password             string
	Email                string
	Roles                []UserRole
	HasTemporaryPassword *bool
}

type createUserRequestPayloadRepeatPassword struct {
	Username             string     `json:"username" validate:"min=1,max=255"`
	Password             string     `json:"password" validate:"min=1,max=140"`
	RepeatedPassword     string     `json:"re_password" validate:"required"`
	Email                string     `json:"email" validate:"min=1,max=254"`
	Roles                []UserRole `json:"user_roles,omitempty"`
	HasTemporaryPassword bool       `json:"has_temporary_password"`
}

type EditUserRequestPayload struct {
	Username                 *string
	Email                    *string
	DateJoined               *time.Time
	IsActive                 *bool
	IsSuperuser              *bool
	IsSubscribedToSDDUpdates *bool
	Roles                    []UserRole
	CurrentPassword          *string
	NewPassword              *string
}

type editUserRequestPayloadRepeatPassword struct {
	Username                 *string    `json:"username,omitempty"`
	Email                    *string    `json:"email,omitempty"`
	DateJoined               *time.Time `json:"date_joined,omitempty"`
	IsActive                 *bool      `json:"is_active,omitempty"`
	IsSuperuser              *bool      `json:"is_superuser,omitempty"`
	IsSubscribedToSDDUpdates *bool      `json:"is_subscribed_to_sdd_updates,omitempty"`
	Roles                    []UserRole `json:"user_roles,omitempty"`
	CurrentPassword          *string    `json:"current_password,omitempty"`
	NewPassword              *string    `json:"new_password,omitempty"`
	RepeatNewPassword        *string    `json:"re_new_password,omitempty"`
}

type resetPasswordResponsePayload struct {
	Password string `json:"password"`
}

func (client *Client) ListUsers(ctx context.Context, credentials *LoginObject) ([]User, error) {
	raw, err := sendRequest[[]rawUser](client, ctx, credentials, http.MethodGet, "/api/users/", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}

	users := make([]User, len(raw))
	for i, rawUser := range raw {
		users[i] = rawUser.toUser()
	}

	return users, nil
}

func (client *Client) CreateUser(
	ctx context.Context,
	credentials *LoginObject,
	payload *CreateUserRequestPayload,
) (User, error) {
	if payload.Roles != nil && len(payload.Roles) == 0 {
		return User{}, fmt.Errorf("cannot create user with zero roles")
	}

	var hasTemporaryPassword bool
	if payload.HasTemporaryPassword == nil {
		hasTemporaryPassword = true
	} else {
		hasTemporaryPassword = *payload.HasTemporaryPassword
	}

	updatedPayload := createUserRequestPayloadRepeatPassword{
		Username:             payload.Username,
		Password:             payload.Password,
		RepeatedPassword:     payload.Password,
		Email:                payload.Email,
		Roles:                payload.Roles,
		HasTemporaryPassword: hasTemporaryPassword,
	}

	raw, err := sendRequest[rawUser](
		client,
		ctx,
		credentials,
		http.MethodPost,
		"/api/users/",
		updatedPayload,
		http.StatusCreated,
	)
	if err != nil {
		return User{}, err
	}

	return raw.toUser(), nil
}

func (client *Client) GetMyUser(ctx context.Context, credentials *LoginObject) (User, error) {
	raw, err := sendRequest[rawUserWithToken](
		client,
		ctx,
		credentials,
		http.MethodGet,
		"/api/users/me/",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return User{}, err
	}

	return raw.toUser(), nil
}

func (client *Client) GetUserByID(ctx context.Context, credentials *LoginObject, id int) (User, error) {
	raw, err := sendRequest[rawUser](
		client,
		ctx,
		credentials,
		http.MethodGet,
		fmt.Sprintf("/api/users/%d/", id),
		nil,
		http.StatusOK,
	)
	if err != nil {
		return User{}, err
	}

	return raw.toUser(), nil
}

func (client *Client) EditUserByID(
	ctx context.Context,
	credentials *LoginObject,
	id int,
	payload *EditUserRequestPayload,
) (User, error) {
	if payload.Roles != nil && len(payload.Roles) == 0 {
		return User{}, fmt.Errorf("cannot edit user to have zero roles")
	} else if payload.CurrentPassword == nil && payload.NewPassword != nil {
		return User{}, fmt.Errorf("must provide current password to change password")
	}

	updatedPayload := editUserRequestPayloadRepeatPassword{
		Username:                 payload.Username,
		Email:                    payload.Email,
		DateJoined:               payload.DateJoined,
		IsActive:                 payload.IsActive,
		IsSuperuser:              payload.IsSuperuser,
		IsSubscribedToSDDUpdates: payload.IsSubscribedToSDDUpdates,
		Roles:                    payload.Roles,
		CurrentPassword:          payload.CurrentPassword,
		NewPassword:              payload.NewPassword,
		RepeatNewPassword:        payload.NewPassword,
	}

	raw, err := sendRequest[rawUser](
		client,
		ctx,
		credentials,
		http.MethodPatch,
		fmt.Sprintf("/api/users/%d/", id),
		updatedPayload,
		http.StatusOK,
	)
	if err != nil {
		return User{}, err
	}

	return raw.toUser(), nil
}

func (client *Client) ResetPassword(ctx context.Context, credentials *LoginObject, id int) (string, error) {
	response, err := sendRequest[resetPasswordResponsePayload](
		client,
		ctx,
		credentials,
		http.MethodPost,
		fmt.Sprintf("/api/users/%d/reset-password/", id),
		nil,
		http.StatusOK,
	)
	if err != nil {
		return "", err
	}

	return response.Password, nil
}
