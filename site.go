package unifi

import (
	"errors"
	"fmt"
)

// A Site is used to access site specific requests of a UniFi Controller
type Site struct {
	// Reference to the controller managing the site
	controller *Controller
	// Site name (as defined in the UniFi controller)
	name string
}

type SiteBuilder interface {
	SetController(controller *Controller) SiteBuilder
	SetName(name string) SiteBuilder
	Build() (*Site, error)
}

type siteBuilder struct {
	site *Site
}

// NewSiteBuilder creates a builder that can be used to create a new Site
func NewSiteBuilder() SiteBuilder {
	return &siteBuilder{
		site: &Site{},
	}
}

// SetController links the Site to the given Controller
func (builder *siteBuilder) SetController(controller *Controller) SiteBuilder {
	builder.site.controller = controller
	return builder
}

// SetName sets the name of the Site
func (builder *siteBuilder) SetName(name string) SiteBuilder {
	builder.site.name = name
	return builder
}

// Build builds the Site and returns a reference to it
func (builder *siteBuilder) Build() (*Site, error) {
	if builder.site.controller == nil {
		return nil, errors.New("site controller is required")
	}

	if len(builder.site.name) == 0 {
		return nil, errors.New("site name is required")
	}
	return builder.site, nil
}

// SetController updates the Controller controlling the Site
func (site *Site) SetController(controller *Controller) error {
	if controller == nil {
		return errors.New("site controller is required")
	}
	site.controller = controller
	return nil
}

// SetName updates the name of the Site
func (site *Site) SetName(name string) error {
	if len(name) == 0 {
		return errors.New("site name can not be empty")
	}
	site.name = name
	return nil
}

// Returns the endpoint for the given path and ID (if not empty) based on the site and Controller
// type
func (site *Site) createEndpointUrl(path string, id string) string {
	var endpoint string
	switch site.controller.controllerType {
	case "UDM-Pro":
		endpoint = fmt.Sprintf("%s/proxy/network/api/s/%s", site.controller.baseUrl, site.name)
	default:
		endpoint = fmt.Sprintf("%s/api/s/%s", site.controller.baseUrl, site.name)
	}

	if len(id) == 0 {
		return fmt.Sprintf("%s/%s", endpoint, path)
	} else {
		return fmt.Sprintf("%s/%s/%s", endpoint, path, id)
	}
}
