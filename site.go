package unifi

import "fmt"

// A Site is used to access site specific requests of a UniFi controller
type Site struct {
	// Site name (as defined in the UniFi controller)
	Name string
	// Reference to the controller managing the site
	Controller *Controller
}

// Returns the endpoint for the given path and ID (if not empty) based on the site and controller
// type
func (site *Site) createEndpointUrl(path string, id string) string {
	var endpoint string
	switch site.Controller.Type {
	case "UDM-Pro":
		endpoint = fmt.Sprintf("%s/proxy/network/api/s/%s", site.Controller.BaseUrl, site.Name)
	default:
		endpoint = fmt.Sprintf("%s/api/s/%s", site.Controller.BaseUrl, site.Name)
	}

	if len(id) == 0 {
		return fmt.Sprintf("%s/%s", endpoint, path)
	} else {
		return fmt.Sprintf("%s/%s/%s", endpoint, path, id)
	}

}
