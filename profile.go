package datamasque

import (
	"context"
	"net/http"
)

type Profile struct {
	GitDirectoryPath *string `json:"git_directory_path"`
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
