package unifi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Generic authentication errors
var (
	UnauthenticatedError = errors.New("unauthenticated, login before continuing")
	SessionExpiredError  = errors.New("session expired, re-login before continuing")
)

// loginInfo is the representation of the body of a login request
type loginInfo struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Login authenticates the user at the UniFi controller using the given username and password and
// saves the received cookie and CSRF token
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

// Logout invalidates the current session credentials (cookie and CSRF token) and clears the
// user credentials
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

	// Clear cookie, CSRF token and user credentials
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

// AssertAuthenticated asserts that the Controller has received authentication and that the current
// session is still valid. Based on the Controller state an UnauthenticatedError,
// SessionExpiredError or no error will be returned
func (controller *Controller) AssertAuthenticated() error {
	if controller.cookie == nil || len(controller.csrfToken) == 0 {
		return UnauthenticatedError
	}

	if controller.cookie.Expires.Before(time.Now()) {
		return SessionExpiredError
	}

	return nil
}

// verifyAuthentication verifies the controller has valid authentication credentials and tries to
// re-authenticate if the current session has expired
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
