package unifi

import (
	"net/http"
	"time"
)

// A Controller is used to manage login state and to send requests linked to a UniFi controller
type Controller struct {
	// The base URL at which the UniFi controller is reachable
	BaseUrl string
	// The cookie received from the UniFi controller after login
	cookie *http.Cookie
	// The CSRF token received from the UniFi controller after login
	csrfToken string
	// Indicates whether TLS verification should be skipped during requests
	SkipTLSVerification bool
	// The type of controller (some controllers use different endpoints e.g. UDM-Pro)
	Type string
	// The timeout to use when making http requests (if not set no timeout will be used)
	RequestTimeout time.Duration
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

// CreateDefaultSite creates and returns the default Site linked to this controller
func (controller *Controller) CreateDefaultSite() Site {
	return Site{
		Name:       "default",
		Controller: controller,
	}
}

// AuthorizeRequest adds the authorization cookie and CSRF token to the given http request
func (controller *Controller) AuthorizeRequest(req *http.Request) {
	req.AddCookie(controller.cookie)
	req.Header.Set("X-CSRF-Token", controller.csrfToken)
}
