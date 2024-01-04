package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type loginData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ToDo: Add remember me
// ToDo: Add re-login? Using cookie expires?

func (controller *Controller) Login(username string, password string) error {
	var loginEndpoint string

	switch controller.Type {
	case "UDM-Pro":
		loginEndpoint = fmt.Sprintf("%s/api/auth/login", controller.BaseUrl)
	default:
		loginEndpoint = fmt.Sprintf("%s/api/login", controller.BaseUrl)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   controller.RequestTimeout,
		Transport: transport,
	}

	loginInfo := loginData{
		Username: username,
		Password: password,
	}

	byteArray, err := json.Marshal(loginInfo)
	if err != nil {
		return err
	}

	payload := bytes.NewBuffer(byteArray)
	req, err := http.NewRequest(`POST`, loginEndpoint, payload)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New(fmt.Sprintf("login failed with response code %d\n", res.StatusCode))
	}

	cookies := res.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "TOKEN" {
			controller.cookie = cookie
			break
		}
	}

	if controller.cookie == nil {
		return errors.New("failed to extract 'TOKEN' cookie from cookies")
	}

	csrfToken := res.Header.Get(`X-CSRF-token`)
	if len(csrfToken) == 0 {
		return errors.New("failed to extract CSRF token from response header")
	}
	controller.csrfToken = csrfToken

	return nil
}

func (controller *Controller) Logout() error {
	var logoutEndpoint string
	switch controller.Type {
	case "UDM-Pro":
		logoutEndpoint = fmt.Sprintf("%s/api/auth/logout", controller.BaseUrl)
	default:
		logoutEndpoint = fmt.Sprintf("%s/api/logout", controller.BaseUrl)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   controller.RequestTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(`POST`, logoutEndpoint, nil)
	if err != nil {
		return err
	}

	// Add authentication
	req.AddCookie(controller.cookie)
	req.Header.Set("X-CSRF-Token", controller.csrfToken)

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New(fmt.Sprintf("logout failed with response code %d\n", res.StatusCode))
	}

	// Resetting cookie and CSRF token as they should no longer be valid
	controller.cookie = nil
	controller.csrfToken = ""
	return nil
}
