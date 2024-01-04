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

type LoginInfo struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	RememberMe bool   `json:"rememberMe,omitempty"`
}

// LoginOptions contains optional login arguments and can be left empty
type LoginOptions struct {
	// Indicates if a long-lasting session is requested
	// (normal session length is 2hr, long-lasting is 30 days) ToDo: Include this info?
	RememberMe bool
	// If RemainAuthenticated is set to true automatic re-authentication with given credentials
	// will be attempted when the session expires
	// (use of long-lasting sessions is recommended to reduce authentication overhead)
	RemainAuthenticated bool
}

// The Login method authenticates the user at the UniFi controller and saves the received cookie
// and CSRF token
func (controller *Controller) Login(
	username string,
	password string,
	options LoginOptions,
) error {
	var endpointUrl string

	switch controller.controllerType {
	case "UDM-Pro":
		endpointUrl = fmt.Sprintf("%s/api/auth/login", controller.baseUrl)
	default:
		endpointUrl = fmt.Sprintf("%s/api/login", controller.baseUrl)
	}

	controller.loginInfo = LoginInfo{
		Username:   username,
		Password:   password,
		RememberMe: options.RememberMe,
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

	// Set remained authenticated option (don't set until authentication was successful)
	controller.remainAuthenticated = options.RemainAuthenticated

	fmt.Printf("Token: %+v\n", controller.cookie)
	fmt.Printf("csrf: %s\n", controller.csrfToken)

	return nil
}

// The Logout invalidates the current session credentials (cookie and CSRF token) and sets the
// remain authenticated option to false
func (controller *Controller) Logout() error {
	err := controller.AssertAuthenticated()
	if err != nil {
		// Resetting cookie and CSRF token as they are not valid
		controller.cookie = nil
		controller.csrfToken = ""

		controller.remainAuthenticated = false

		// No need to attempt logout when not authenticated
		return nil
	}

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

	// Resetting cookie and CSRF token as they are no longer valid
	controller.cookie = nil
	controller.csrfToken = ""

	controller.remainAuthenticated = false

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
// If the session has expired and remain authenticated was enabled re-authentication will be
// attempted
func (controller *Controller) verifyAuthentication() error {
	err := controller.AssertAuthenticated()

	if controller.remainAuthenticated && errors.Is(err, SessionExpiredError) {
		err = controller.Login(
			controller.loginInfo.Username,
			controller.loginInfo.Password,
			LoginOptions{
				RememberMe:          controller.loginInfo.RememberMe,
				RemainAuthenticated: true,
			},
		)
		if err != nil {
			return err
		}
	}

	// Return error (either original or login error)
	return err
}
