package unifi

// Meta is included in most responses and contain extra information about the request
type Meta struct {
	// The response code indicating the response status
	Rc string `json:"rc"`
	// The duplicate firewall group name if a duplicate group name was used
	Name string `json:"name,omitempty"`
	// The duplicate firewall rule index if a duplicate rule index was used
	RuleIndex int `json:"rule_index,omitempty"`
	// An error message describing what went wrong
	Msg string `json:"msg,omitempty"`
}

// ValidationError indicates an error occurred when trying to validate a field
type ValidationError struct {
	// The field on which the validation failed
	Field string `json:"field,omitempty"`
	// The expected pattern the field should adhere to
	Pattern string `json:"pattern,omitempty"`
}

// DataValidationError is the representation of an error in the data array of a request response
type DataValidationError struct {
	ValidationError ValidationError `json:"validationError,omitempty"`
	// The response code indicating the response status
	Rc string `json:"rc,omitempty"`
	// An error message describing what went wrong
	Msg string `json:"msg,omitempty"`
}
