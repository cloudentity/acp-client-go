// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListScriptExecutionPointsReader is a Reader for the ListScriptExecutionPoints structure.
type ListScriptExecutionPointsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListScriptExecutionPointsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListScriptExecutionPointsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListScriptExecutionPointsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListScriptExecutionPointsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListScriptExecutionPointsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/script-execution-points] listScriptExecutionPoints", response, response.Code())
	}
}

// NewListScriptExecutionPointsOK creates a ListScriptExecutionPointsOK with default headers values
func NewListScriptExecutionPointsOK() *ListScriptExecutionPointsOK {
	return &ListScriptExecutionPointsOK{}
}

/*
ListScriptExecutionPointsOK describes a response with status code 200, with default header values.

Script execution points
*/
type ListScriptExecutionPointsOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ScriptExecutionPoints
}

// IsSuccess returns true when this list script execution points o k response has a 2xx status code
func (o *ListScriptExecutionPointsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list script execution points o k response has a 3xx status code
func (o *ListScriptExecutionPointsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list script execution points o k response has a 4xx status code
func (o *ListScriptExecutionPointsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list script execution points o k response has a 5xx status code
func (o *ListScriptExecutionPointsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list script execution points o k response a status code equal to that given
func (o *ListScriptExecutionPointsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list script execution points o k response
func (o *ListScriptExecutionPointsOK) Code() int {
	return 200
}

func (o *ListScriptExecutionPointsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsOK %s", 200, payload)
}

func (o *ListScriptExecutionPointsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsOK %s", 200, payload)
}

func (o *ListScriptExecutionPointsOK) GetPayload() *models.ScriptExecutionPoints {
	return o.Payload
}

func (o *ListScriptExecutionPointsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ScriptExecutionPoints)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptExecutionPointsUnauthorized creates a ListScriptExecutionPointsUnauthorized with default headers values
func NewListScriptExecutionPointsUnauthorized() *ListScriptExecutionPointsUnauthorized {
	return &ListScriptExecutionPointsUnauthorized{}
}

/*
ListScriptExecutionPointsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListScriptExecutionPointsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list script execution points unauthorized response has a 2xx status code
func (o *ListScriptExecutionPointsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list script execution points unauthorized response has a 3xx status code
func (o *ListScriptExecutionPointsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list script execution points unauthorized response has a 4xx status code
func (o *ListScriptExecutionPointsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list script execution points unauthorized response has a 5xx status code
func (o *ListScriptExecutionPointsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list script execution points unauthorized response a status code equal to that given
func (o *ListScriptExecutionPointsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list script execution points unauthorized response
func (o *ListScriptExecutionPointsUnauthorized) Code() int {
	return 401
}

func (o *ListScriptExecutionPointsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsUnauthorized %s", 401, payload)
}

func (o *ListScriptExecutionPointsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsUnauthorized %s", 401, payload)
}

func (o *ListScriptExecutionPointsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptExecutionPointsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptExecutionPointsForbidden creates a ListScriptExecutionPointsForbidden with default headers values
func NewListScriptExecutionPointsForbidden() *ListScriptExecutionPointsForbidden {
	return &ListScriptExecutionPointsForbidden{}
}

/*
ListScriptExecutionPointsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListScriptExecutionPointsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list script execution points forbidden response has a 2xx status code
func (o *ListScriptExecutionPointsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list script execution points forbidden response has a 3xx status code
func (o *ListScriptExecutionPointsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list script execution points forbidden response has a 4xx status code
func (o *ListScriptExecutionPointsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list script execution points forbidden response has a 5xx status code
func (o *ListScriptExecutionPointsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list script execution points forbidden response a status code equal to that given
func (o *ListScriptExecutionPointsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list script execution points forbidden response
func (o *ListScriptExecutionPointsForbidden) Code() int {
	return 403
}

func (o *ListScriptExecutionPointsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsForbidden %s", 403, payload)
}

func (o *ListScriptExecutionPointsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsForbidden %s", 403, payload)
}

func (o *ListScriptExecutionPointsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptExecutionPointsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptExecutionPointsTooManyRequests creates a ListScriptExecutionPointsTooManyRequests with default headers values
func NewListScriptExecutionPointsTooManyRequests() *ListScriptExecutionPointsTooManyRequests {
	return &ListScriptExecutionPointsTooManyRequests{}
}

/*
ListScriptExecutionPointsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListScriptExecutionPointsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list script execution points too many requests response has a 2xx status code
func (o *ListScriptExecutionPointsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list script execution points too many requests response has a 3xx status code
func (o *ListScriptExecutionPointsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list script execution points too many requests response has a 4xx status code
func (o *ListScriptExecutionPointsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list script execution points too many requests response has a 5xx status code
func (o *ListScriptExecutionPointsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list script execution points too many requests response a status code equal to that given
func (o *ListScriptExecutionPointsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list script execution points too many requests response
func (o *ListScriptExecutionPointsTooManyRequests) Code() int {
	return 429
}

func (o *ListScriptExecutionPointsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsTooManyRequests %s", 429, payload)
}

func (o *ListScriptExecutionPointsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/script-execution-points][%d] listScriptExecutionPointsTooManyRequests %s", 429, payload)
}

func (o *ListScriptExecutionPointsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptExecutionPointsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
