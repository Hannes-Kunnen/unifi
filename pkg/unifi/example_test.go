package unifi_test

import (
	"fmt"
	"github.com/Hannes-Kunnen/unifi/pkg/unifi"
	"time"
)

func Example() {
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
