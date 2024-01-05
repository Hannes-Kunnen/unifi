package unifi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var UnauthenticatedError = errors.New("cookie or CSRF token not set, login before continuing")
var SessionExpiredError = errors.New("cookie expired, re-login before continuing")

type loginInfo struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// The Login method authenticates the user at the UniFi controller and saves the received cookie
// and CSRF token
func (controller *Controller) Login(
	username string,
	password string,
) error {
	var endpointUrl string

	switch controller.controllerType {
	case "UDM-Pro":
		endpointUrl = fmt.Sprintf("%s/api/auth/login", controller.baseUrl)
	default:
		endpointUrl = fmt.Sprintf("%s/api/login", controller.baseUrl)
	}

	controller.loginInfo = loginInfo{
		Username: username,
		Password: password,
	}

	byteArray, err := json.Marshal(controller.loginInfo)
	if err != nil {
		return err
	}

	payload := bytes.NewBuffer(byteArray)
	req, err := http.NewRequest(`POST`, endpointUrl, payload)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := controller.httpClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New(fmt.Sprintf("login failed with response code %d", res.StatusCode))
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

	controller.csrfToken = res.Header.Get(`X-CSRF-token`)
	if len(controller.csrfToken) == 0 {
		return errors.New("failed to extract CSRF token from response header")
	}

	return nil
}

// The Logout invalidates the current session credentials (cookie and CSRF token) and clears the
// credentials
func (controller *Controller) Logout() error {
	err := controller.AssertAuthenticated()

	// Only perform logout request when logged in
	if err == nil {
		var endpointUrl string
		switch controller.controllerType {
		case "UDM-Pro":
			endpointUrl = fmt.Sprintf("%s/api/auth/logout", controller.baseUrl)
		default:
			endpointUrl = fmt.Sprintf("%s/api/logout", controller.baseUrl)
		}

		req, err := http.NewRequest(`POST`, endpointUrl, nil)
		if err != nil {
			return err
		}

		controller.AuthorizeRequest(req)

		res, err := controller.httpClient.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode != 200 {
			return errors.New(fmt.Sprintf("logout failed with response code %d\n", res.StatusCode))
		}
	}

	// Clear cookie, CSRF token and credentials
	controller.cookie = nil
	controller.csrfToken = ""
	controller.loginInfo.Username = ""
	controller.loginInfo.Password = ""

	return nil
}

// AuthorizeRequest adds the authorization cookie and CSRF token to the given http request
func (controller *Controller) AuthorizeRequest(req *http.Request) {
	req.AddCookie(controller.cookie)
	req.Header.Set("X-CSRF-Token", controller.csrfToken)
}

func (controller *Controller) AssertAuthenticated() error {
	if controller.cookie == nil || len(controller.csrfToken) == 0 {
		return UnauthenticatedError
	}

	if controller.cookie.Expires.Before(time.Now()) {
		return SessionExpiredError
	}

	return nil
}

// Verifies the controller has valid authentication.
// If the session has expired re-authentication will be attempted
func (controller *Controller) verifyAuthentication() error {
	err := controller.AssertAuthenticated()

	if errors.Is(err, SessionExpiredError) {
		err = controller.Login(
			controller.loginInfo.Username,
			controller.loginInfo.Password,
		)
		if err != nil {
			return err
		}
	}

	// Return error (either original or login error)
	return err
}
