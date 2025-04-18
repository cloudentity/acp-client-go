// Code generated by go-swagger; DO NOT EDIT.

package environment

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

// GetWorkspaceEnvironmentReader is a Reader for the GetWorkspaceEnvironment structure.
type GetWorkspaceEnvironmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetWorkspaceEnvironmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetWorkspaceEnvironmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetWorkspaceEnvironmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetWorkspaceEnvironmentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetWorkspaceEnvironmentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/environment] getWorkspaceEnvironment", response, response.Code())
	}
}

// NewGetWorkspaceEnvironmentOK creates a GetWorkspaceEnvironmentOK with default headers values
func NewGetWorkspaceEnvironmentOK() *GetWorkspaceEnvironmentOK {
	return &GetWorkspaceEnvironmentOK{}
}

/*
GetWorkspaceEnvironmentOK describes a response with status code 200, with default header values.

Environment
*/
type GetWorkspaceEnvironmentOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Environment
}

// IsSuccess returns true when this get workspace environment o k response has a 2xx status code
func (o *GetWorkspaceEnvironmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get workspace environment o k response has a 3xx status code
func (o *GetWorkspaceEnvironmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get workspace environment o k response has a 4xx status code
func (o *GetWorkspaceEnvironmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get workspace environment o k response has a 5xx status code
func (o *GetWorkspaceEnvironmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get workspace environment o k response a status code equal to that given
func (o *GetWorkspaceEnvironmentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get workspace environment o k response
func (o *GetWorkspaceEnvironmentOK) Code() int {
	return 200
}

func (o *GetWorkspaceEnvironmentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentOK %s", 200, payload)
}

func (o *GetWorkspaceEnvironmentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentOK %s", 200, payload)
}

func (o *GetWorkspaceEnvironmentOK) GetPayload() *models.Environment {
	return o.Payload
}

func (o *GetWorkspaceEnvironmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Environment)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetWorkspaceEnvironmentUnauthorized creates a GetWorkspaceEnvironmentUnauthorized with default headers values
func NewGetWorkspaceEnvironmentUnauthorized() *GetWorkspaceEnvironmentUnauthorized {
	return &GetWorkspaceEnvironmentUnauthorized{}
}

/*
GetWorkspaceEnvironmentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetWorkspaceEnvironmentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get workspace environment unauthorized response has a 2xx status code
func (o *GetWorkspaceEnvironmentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get workspace environment unauthorized response has a 3xx status code
func (o *GetWorkspaceEnvironmentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get workspace environment unauthorized response has a 4xx status code
func (o *GetWorkspaceEnvironmentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get workspace environment unauthorized response has a 5xx status code
func (o *GetWorkspaceEnvironmentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get workspace environment unauthorized response a status code equal to that given
func (o *GetWorkspaceEnvironmentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get workspace environment unauthorized response
func (o *GetWorkspaceEnvironmentUnauthorized) Code() int {
	return 401
}

func (o *GetWorkspaceEnvironmentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentUnauthorized %s", 401, payload)
}

func (o *GetWorkspaceEnvironmentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentUnauthorized %s", 401, payload)
}

func (o *GetWorkspaceEnvironmentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetWorkspaceEnvironmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetWorkspaceEnvironmentForbidden creates a GetWorkspaceEnvironmentForbidden with default headers values
func NewGetWorkspaceEnvironmentForbidden() *GetWorkspaceEnvironmentForbidden {
	return &GetWorkspaceEnvironmentForbidden{}
}

/*
GetWorkspaceEnvironmentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetWorkspaceEnvironmentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get workspace environment forbidden response has a 2xx status code
func (o *GetWorkspaceEnvironmentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get workspace environment forbidden response has a 3xx status code
func (o *GetWorkspaceEnvironmentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get workspace environment forbidden response has a 4xx status code
func (o *GetWorkspaceEnvironmentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get workspace environment forbidden response has a 5xx status code
func (o *GetWorkspaceEnvironmentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get workspace environment forbidden response a status code equal to that given
func (o *GetWorkspaceEnvironmentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get workspace environment forbidden response
func (o *GetWorkspaceEnvironmentForbidden) Code() int {
	return 403
}

func (o *GetWorkspaceEnvironmentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentForbidden %s", 403, payload)
}

func (o *GetWorkspaceEnvironmentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentForbidden %s", 403, payload)
}

func (o *GetWorkspaceEnvironmentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetWorkspaceEnvironmentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetWorkspaceEnvironmentTooManyRequests creates a GetWorkspaceEnvironmentTooManyRequests with default headers values
func NewGetWorkspaceEnvironmentTooManyRequests() *GetWorkspaceEnvironmentTooManyRequests {
	return &GetWorkspaceEnvironmentTooManyRequests{}
}

/*
GetWorkspaceEnvironmentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetWorkspaceEnvironmentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get workspace environment too many requests response has a 2xx status code
func (o *GetWorkspaceEnvironmentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get workspace environment too many requests response has a 3xx status code
func (o *GetWorkspaceEnvironmentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get workspace environment too many requests response has a 4xx status code
func (o *GetWorkspaceEnvironmentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get workspace environment too many requests response has a 5xx status code
func (o *GetWorkspaceEnvironmentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get workspace environment too many requests response a status code equal to that given
func (o *GetWorkspaceEnvironmentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get workspace environment too many requests response
func (o *GetWorkspaceEnvironmentTooManyRequests) Code() int {
	return 429
}

func (o *GetWorkspaceEnvironmentTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentTooManyRequests %s", 429, payload)
}

func (o *GetWorkspaceEnvironmentTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/environment][%d] getWorkspaceEnvironmentTooManyRequests %s", 429, payload)
}

func (o *GetWorkspaceEnvironmentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetWorkspaceEnvironmentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
