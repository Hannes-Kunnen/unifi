package unifi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// A ControllerBuilder helps to build a Controller
type ControllerBuilder struct {
	baseUrl             string
	controllerType      string
	requestTimeout      time.Duration
	skipTLSVerification bool
}

// SetBaseUrl sets the URL at which the UniFi controller is reachable
func (builder *ControllerBuilder) SetBaseUrl(baseUrl string) *ControllerBuilder {
	builder.baseUrl = baseUrl
	return builder
}

// SetControllerType sets the type of UniFi controller (some controllers use different endpoints)
// (not set uses default endpoints)
func (builder *ControllerBuilder) SetControllerType(controllerType string) *ControllerBuilder {
	builder.controllerType = controllerType
	return builder
}

// SetRequestTimout sets the timeout to use when making http requests (default no timeout)
func (builder *ControllerBuilder) SetRequestTimout(timeout time.Duration) *ControllerBuilder {
	builder.requestTimeout = timeout
	return builder
}

// SetTlsVerification indicates whether TLS verification should be used (default true)
func (builder *ControllerBuilder) SetTlsVerification(verificationOn bool) *ControllerBuilder {
	builder.skipTLSVerification = !verificationOn
	return builder
}

// Build builds the Controller and returns a reference to it
func (builder *ControllerBuilder) Build() (*Controller, error) {
	_, err := url.ParseRequestURI(builder.baseUrl)
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
	if builder.requestTimeout < 0 {
		return nil, errors.New("request timout can not be smaller than 0 (no timeout)")
	}

	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: builder.skipTLSVerification},
	}

	httpClient := &http.Client{
		Timeout:   builder.requestTimeout,
		Transport: httpTransport,
	}

	controller := &Controller{
		baseUrl:        builder.baseUrl,
		controllerType: builder.controllerType,
		httpClient:     httpClient,
		httpTransport:  httpTransport,
	}

	return controller, nil
}
