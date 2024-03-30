package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

type Umami struct {
	Host           string
	Namespace      string
	AdminSecretRef string
}

type authPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string `json:"token"`
	User  struct {
		Id        string `json:"id"`
		Username  string `json:"username"`
		CreatedAt string `json:"created_at"`
	} `json:"user"`
}

type umamiWebsite struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

type websitesListResponse struct {
	Count    int            `json:"count"`
	Data     []umamiWebsite `json:"data"`
	OrderBy  string         `json:"orderBy"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

type websiteCreatePayload struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}
type websiteCreateResponse = umamiWebsite

type websiteUpdatePayload struct {
	Name   string `json:"name",omitempty`
	Domain string `json:"domain",omitempty`
}

type websiteUpdateResponse = umamiWebsite

func apiQuery[O any](u *Umami, path, token string) (O, error) {
	url, _ := url.JoinPath(u.Host, path)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return *new(O), fmt.Errorf("while making the request: %w", err)
	}

	var output O
	err = json.NewDecoder(response.Body).Decode(&output)
	if err != nil {
		return *new(O), fmt.Errorf("while decoding the response: %w", err)
	}

	return output, nil
}

func apiRequest[I, O any](u *Umami, method, path, token string, input I) (O, error) {
	url, _ := url.JoinPath(u.Host, path)
	var request *http.Request
	payload, _ := json.Marshal(input)
	request, _ = http.NewRequest(method, url, bytes.NewBuffer(payload))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return *new(O), fmt.Errorf("while making the request: %w", err)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return *new(O), fmt.Errorf("while reading response body: %w", err)
	}

	var output O
	err = json.Unmarshal(bodyBytes, &output)
	if err != nil {
		return *new(O), fmt.Errorf("while decoding the response: %w (response was %q)", err, string(bodyBytes))
	}

	return output, nil
}
