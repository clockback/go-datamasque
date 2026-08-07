package datamasque

import (
	"context"
	"net/http"
)

type Profile struct {
	GitDirectoryPath *string `json:"git_directory_path"`
}

type GitDirectoryPathSetting struct {
	Path *string
}

type UpdateMyProfilePayload struct {
	GitDirectoryPath *GitDirectoryPathSetting
}

func (client *Client) GetMyProfile(ctx context.Context, credentials *LoginObject) (Profile, error) {
	return sendRequest[Profile](
		client,
		ctx,
		credentials,
		http.MethodGet,
		"/api/users/me/profile/",
		nil,
		http.StatusOK,
	)
}

func (client *Client) UpdateMyProfile(
	ctx context.Context,
	credentials *LoginObject,
	payload *UpdateMyProfilePayload,
) error {
	updatedPayload := map[string]any{}

	if payload.GitDirectoryPath != nil {
		updatedPayload["git_directory_path"] = payload.GitDirectoryPath.Path
	}

	return client.sendRequestStatusNoContent(
		ctx,
		credentials,
		http.MethodPost,
		"/api/users/me/profile/",
		updatedPayload,
	)
}
