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
	"reflect"
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

func (client *Client) validateResult(target any) error {
	val := reflect.ValueOf(target)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			if err := client.validate.Struct(val.Index(i).Interface()); err != nil {
				return err
			}
		}
	case reflect.Struct:
		return client.validate.Struct(target)
	}

	return nil
}

func sendRequest[T any](
	client *Client,
	ctx context.Context,
	credentials *LoginObject,
	method string,
	path string,
	body any,
	expectedStatus int,
) (T, error) {
	var result T

	fullURL := client.BaseURL.JoinPath(path).String()

	var bodyReader io.Reader
	if body != nil {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return result, fmt.Errorf("failed to encode request body: %w", err)
		}
		bodyReader = buf
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.doAuthenticated(credentials, req)
	if err != nil {
		return result, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		return result, fmt.Errorf("request failed with status %s (%d)", resp.Status, resp.StatusCode)
	} else if resp.StatusCode == http.StatusNoContent {
		return result, nil
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return result, fmt.Errorf("expected JSON response, got Content-Type: %s", contentType)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("failed to decode response body: %w", err)
	}

	if err := client.validateResult(&result); err != nil {
		return result, fmt.Errorf("failed validation on response body: %w", err)
	}

	return result, nil
}

func (client *Client) sendRequestStatusNoContent(
	ctx context.Context,
	credentials *LoginObject,
	method string,
	path string,
	body any,
) error {
	_, err := sendRequest[struct{}](client, ctx, credentials, method, path, body, http.StatusNoContent)
	return err
}
