# Unifi

Unifi is a tool to manage one or more UniFi (multi-site) controller(s) using GO.

## Documentation

### Getting started

To get started we first have to create a `Controller` using the steps below:
1. Create a `ControllerBuilder`
2. Configure the builder to work with your specific UniFi controller
3. Build the `Controller`

Once it is created the `Controller.Login` function can be used to authenticate using the username and password of a (local) UniFi user (Two-factor authentication is currently not supported). 

That's it, you can now start making request to your UniFi controller.
You can use one of the predefined request (see Go package documentation), keep in mind that a lot of request require a `Site`.
This can be easily created using the `Controller.CreateDefaultSite` or the `Controller.CreateSite` function, for most UniFi controllers the default site will be used.
If you can't find what you are looking for or just want to have more control you can use the `Controller.AuthorizeRequest` method to add the authorization parameters to the given http request. 

See [print all firewall rules](#print-all-firewall-rules) for an example implementation.

## Examples

### Print all firewall rules

```go
package main

import (
	"fmt"
	"github.com/Hannes-Kunnen/unifi/pkg/unifi"
	"time"
)

func main() {
	// Create controller builder.
	controllerBuilder := unifi.ControllerBuilder{}
	// Configure the builder and build the controller.
	controller, err := controllerBuilder.
		SetBaseUrl("https://unifi").
		SetControllerType("UDM-Pro").
		SetRequestTimout(30 * time.Second).
		SetTlsVerification(false).
		Build()
	if err != nil {
		fmt.Printf("Error while building controller: %s\n", err)
		return
	}

	// Login using user credentials.
	err = controller.Login("unifi-username", "unifi-password")
	if err != nil {
		fmt.Printf("Error during login: %s\n", err)
		return
	}
	fmt.Println("Login successful")

	// Logout when all actions are completed.
	defer func(controller *unifi.Controller) {
		err := controller.Logout()
		if err != nil {
			fmt.Printf("Error during logout: %s\n", err)
			return
		}
		fmt.Println("Logout successful")
	}(controller)

	// Create a default site.
	site := controller.CreateDefaultSite()
	
	// Retrieve all firewall rules of the site.
	response, err := site.GetAllFirewallRules()
	if err != nil {
		fmt.Printf("Error while retreiving firewall rules: %s\n", err)
		return
	}
	for index, responseData := range response.Data {
		fmt.Printf("Rule %d: %+v\n", index, *responseData.FirewallRule)
	}
}

```
