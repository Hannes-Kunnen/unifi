package unifi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// A Controller is used to manage login state and to send requests linked to a UniFi controller
type Controller struct {
	// The URL at which the UniFi controller is reachable
	baseUrl string
	// The type of Controller (some controllers use different endpoints e.g. UDM-Pro)
	controllerType string
	// The cookie received from the UniFi controller after login
	cookie *http.Cookie
	// The CSRF token received from the UniFi controller after login
	csrfToken string
	// The http client used to make the requests
	httpClient *http.Client
	// The transport used by the http client when making the request
	httpTransport *http.Transport
	// The user login info
	loginInfo loginInfo
}

// A ControllerBuilder provides the ability to build a Controller
type ControllerBuilder interface {
	SetBaseUrl(baseUrl string) ControllerBuilder
	SetControllerType(controllerType string) ControllerBuilder
	SetRequestTimout(timeout time.Duration) ControllerBuilder
	SetTlsVerification(verify bool) ControllerBuilder
	Build() (*Controller, error)
}

// A controllerBuilder helps to build a Controller
type controllerBuilder struct {
	controller *Controller
}

// NewControllerBuilder returns a builder that can be used to create a new Controller
func NewControllerBuilder() ControllerBuilder {
	return &controllerBuilder{
		controller: &Controller{},
	}
}

// SetBaseUrl sets the URL at which the UniFi controller is reachable
func (builder *controllerBuilder) SetBaseUrl(baseUrl string) ControllerBuilder {
	builder.controller.baseUrl = baseUrl
	return builder
}

// SetControllerType sets the type of UniFi controller (some controllers use different endpoints)
// (not set uses default endpoints)
func (builder *controllerBuilder) SetControllerType(controllerType string) ControllerBuilder {
	builder.controller.controllerType = controllerType
	return builder
}

// SetRequestTimout sets the timeout to use when making http requests (default no timeout)
func (builder *controllerBuilder) SetRequestTimout(timeout time.Duration) ControllerBuilder {
	if builder.controller.httpClient == nil {
		builder.controller.httpClient = &http.Client{
			Timeout: timeout,
		}
	} else {
		builder.controller.httpClient.Timeout = timeout
	}

	return builder
}

// SetTlsVerification indicates whether TLS verification should be used (default true)
func (builder *controllerBuilder) SetTlsVerification(verify bool) ControllerBuilder {
	if builder.controller.httpTransport == nil {
		builder.controller.httpTransport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify},
		}
	} else {
		builder.controller.httpTransport.TLSClientConfig.InsecureSkipVerify = !verify
	}

	return builder
}

// Build builds the Controller and returns a reference to it
func (builder *controllerBuilder) Build() (*Controller, error) {
	_, err := url.ParseRequestURI(builder.controller.baseUrl)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			return nil, errors.New(
				fmt.Sprintf("failed to %s url %q: %s", urlError.Op, urlError.URL, urlError.Err),
			)
		}
		return nil, err
	}

	// Verify request timeout is valid (negative timout is not documented)
	if builder.controller.httpClient.Timeout < 0 {
		return nil, errors.New("request timout can not be smaller than 0 (no timeout)")
	}

	// Create HTTP client if not exists
	if builder.controller.httpClient == nil {
		builder.controller.httpClient = &http.Client{
			Transport: builder.controller.httpTransport,
		}
	} else {
		builder.controller.httpClient.Transport = builder.controller.httpTransport
	}

	return builder.controller, nil
}

// SetBaseUrl updates the URL at which the UniFi controller is reachable
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

// SetControllerType updates the type of the UniFi controller
func (controller *Controller) SetControllerType(controllerType string) {
	controller.controllerType = controllerType
}

// SetRequestTimout updates the timeout to use when making http requests
func (controller *Controller) SetRequestTimout(timeout time.Duration) error {
	// Verify request timeout is valid (negative timout is not documented)
	if timeout < 0 {
		return errors.New("timeout can not be smaller than 0")
	}
	controller.httpClient.Timeout = timeout
	return nil
}

// SetTlsVerification updates whether TLS verification will be used
func (controller *Controller) SetTlsVerification(verify bool) {
	controller.httpTransport.TLSClientConfig.InsecureSkipVerify = !verify
}

// CreateDefaultSite creates and returns the default Site linked to this Controller
func (controller *Controller) CreateDefaultSite() Site {
	return Site{
		name:       "default",
		controller: controller,
	}
}
