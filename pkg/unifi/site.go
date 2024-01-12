package unifi

import (
	"errors"
	"fmt"
)

// A Site is used to access site specific requests of a UniFi controller.
type Site struct {
	// Reference to the controller managing the site.
	controller *Controller
	// Site name (as defined in the UniFi controller).
	name string
}

// SetController updates the [Controller] controlling the [Site] to the given controller.
// It will return an error if the given controller is empty.
func (site *Site) SetController(controller *Controller) error {
	if controller == nil {
		return errors.New("site controller is required")
	}
	site.controller = controller
	return nil
}

// SetName updates the name of the [Site] to the given name.
// It will return an error if the given name is empty
func (site *Site) SetName(name string) error {
	if name == "" {
		return errors.New("site name can not be empty")
	}
	site.name = name
	return nil
}

// Returns the endpoint for the given path and ID (if not empty) based on the [Site] and
// [Controller] type.
func (site *Site) createEndpointUrl(path string, id string) string {
	var endpoint string
	switch site.controller.controllerType {
	case "UDM-Pro":
		endpoint = fmt.Sprintf("%s/proxy/network/api/s/%s", site.controller.baseUrl, site.name)
	default:
		endpoint = fmt.Sprintf("%s/api/s/%s", site.controller.baseUrl, site.name)
	}

	if id == "" {
		return fmt.Sprintf("%s/%s", endpoint, path)
	} else {
		return fmt.Sprintf("%s/%s/%s", endpoint, path, id)
	}
}
