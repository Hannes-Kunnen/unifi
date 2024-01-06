package unifi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// A Controller is used to manage login state and to send requests linked to a UniFi Controller
type Controller struct {
	// The base URL at which the UniFi Controller is reachable
	baseUrl string
	// The http client used to make the requests
	httpClient *http.Client
	// The type of Controller (some controllers use different endpoints e.g. UDM-Pro)
	controllerType string
	// The cookie received from the UniFi Controller after login
	cookie *http.Cookie
	// The CSRF token received from the UniFi Controller after login
	csrfToken string
	// Contains the users login info
	loginInfo loginInfo
	// The timeout to use when making http requests
	requestTimeout time.Duration
	// Indicates whether TLS verification should be skipped during requests
	skipTLSVerification bool
}

type ControllerBuilder interface {
	SetBaseUrl(baseUrl string) ControllerBuilder
	SetControllerType(controllerType string) ControllerBuilder
	SetRequestTimout(timeout time.Duration) ControllerBuilder
	SetTlsVerification(verify bool) ControllerBuilder
	Build() (*Controller, error)
}

type controllerBuilder struct {
	controller *Controller
}

func NewControllerBuilder() ControllerBuilder {
	return &controllerBuilder{
		controller: &Controller{},
	}
}

func (builder *controllerBuilder) SetBaseUrl(baseUrl string) ControllerBuilder {
	builder.controller.baseUrl = baseUrl
	return builder
}

func (builder *controllerBuilder) SetControllerType(controllerType string) ControllerBuilder {
	builder.controller.controllerType = controllerType
	return builder
}

func (builder *controllerBuilder) SetRequestTimout(timeout time.Duration) ControllerBuilder {
	builder.controller.requestTimeout = timeout
	return builder
}

func (builder *controllerBuilder) SetTlsVerification(verify bool) ControllerBuilder {
	builder.controller.skipTLSVerification = !verify
	return builder
}

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

	// Verify request timeout is valid
	if builder.controller.requestTimeout < 0 {
		return nil, errors.New("request timout can not be smaller than 0 (no timeout)")
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: builder.controller.skipTLSVerification},
	}
	builder.controller.httpClient = &http.Client{
		Timeout:   builder.controller.requestTimeout,
		Transport: transport,
	}

	return builder.controller, nil
}

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

func (controller *Controller) SetControllerType(controllerType string) {
	controller.controllerType = controllerType
}

func (controller *Controller) SetRequestTimout(timeout time.Duration) error {
	if timeout < 0 {
		return errors.New("timeout can not be smaller than 0")
	}
	controller.requestTimeout = timeout
	controller.httpClient.Timeout = controller.requestTimeout
	return nil
}

func (controller *Controller) SetTlsVerification(verify bool) {
	controller.skipTLSVerification = !verify
	controller.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: controller.skipTLSVerification},
	}
}

// Meta is included in most responses and seems to contain extra information about the request
type Meta struct {
	// The response code (text) to indicate the response status
	Rc string `json:"rc"`
	// ToDo
	Name string `json:"name,omitempty"`
	// An error message to indicated what went wrong
	Msg string `json:"msg,omitempty"`
}

// CreateDefaultSite creates and returns the default Site linked to this Controller
func (controller *Controller) CreateDefaultSite() Site {
	return Site{
		name:       "default",
		controller: controller,
	}
}
