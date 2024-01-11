package unifi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// A Controller is used to manage login state and to send requests linked to a UniFi controller.
type Controller struct {
	// The URL at which the UniFi controller is reachable.
	baseUrl string
	// The type of Controller (some controllers use different endpoints e.g. UDM-Pro).
	controllerType string
	// The cookie received from the UniFi controller after login.
	cookie *http.Cookie
	// The CSRF token received from the UniFi controller after login.
	csrfToken string
	// The http client used to make the requests.
	httpClient *http.Client
	// The transport used by the http client when making the request.
	httpTransport *http.Transport
	// The user login info.
	loginInfo loginInfo
}

// SetBaseUrl updates the URL at which the UniFi controller is reachable.
func (controller *Controller) SetBaseUrl(baseUrl string) error {
	_, err := url.ParseRequestURI(baseUrl)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			return errors.New(
				fmt.Sprintf("failed to %s url %q: %s", urlError.Op, urlError.URL, urlError.Err),
			)
		}
		return err
	}
	controller.baseUrl = baseUrl
	return nil
}

// SetControllerType updates the type of the UniFi controller.
func (controller *Controller) SetControllerType(controllerType string) {
	controller.controllerType = controllerType
}

// SetRequestTimout updates the timeout to use when making http requests.
func (controller *Controller) SetRequestTimout(timeout time.Duration) error {
	// Verify request timeout is valid (negative timout is not documented).
	if timeout < 0 {
		return errors.New("timeout can not be smaller than 0")
	}
	controller.httpClient.Timeout = timeout
	return nil
}

// SetTlsVerification updates whether TLS verification will be used.
func (controller *Controller) SetTlsVerification(verify bool) {
	controller.httpTransport.TLSClientConfig.InsecureSkipVerify = !verify
}

// CreateDefaultSite creates and returns a reference to the default Site linked to this Controller.
func (controller *Controller) CreateDefaultSite() *Site {
	return &Site{
		name:       "default",
		controller: controller,
	}
}

// CreateSite creates and returns a reference to the Site with given name linked to this
// Controller.
func (controller *Controller) CreateSite(name string) Site {
	return Site{
		name:       name,
		controller: controller,
	}
}

// Executes a request with given method to the given endpoint URL, if a body is included it will be
// transformed to JSON and added as a request body. If responseData is set the response body will
// be parsed and the value will be stored in this variable.
func (controller *Controller) execute(
	method string,
	endpointUrl string,
	body any,
	responseData any,
) (*http.Response, error) {
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequest(method, endpointUrl, http.NoBody)
	} else {
		requestBodyByteArray, marshalError := json.Marshal(body)
		if marshalError != nil {
			return nil, marshalError
		}

		req, err = http.NewRequest(method, endpointUrl, bytes.NewBuffer(requestBodyByteArray))
	}
	if err != nil {
		return nil, err
	}

	err = controller.AuthorizeRequest(req)
	if err != nil {
		return nil, err
	}

	if body != nil && (method == http.MethodPost || method == http.MethodPut) {
		req.Header.Set("Content-Type", "application/json")
	}

	var res *http.Response
	res, err = controller.httpClient.Do(req)
	if err != nil {
		return res, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	// If response contains a CSRF token, replace the current one (in case it changes).
	newCsrfToken := res.Header.Get(`X-CSRF-token`)
	if newCsrfToken != "" {
		controller.csrfToken = newCsrfToken
	}

	// If no response data reference is included, the body is not parsed.
	if responseData == nil {
		return res, nil
	}

	responseBodyByteArray, err := io.ReadAll(res.Body)
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(responseBodyByteArray, responseData)
	if err != nil {
		return res, err
	}

	return res, nil
}
