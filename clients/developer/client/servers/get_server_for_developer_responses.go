// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/developer/models"
)

// GetServerForDeveloperReader is a Reader for the GetServerForDeveloper structure.
type GetServerForDeveloperReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetServerForDeveloperReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetServerForDeveloperOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetServerForDeveloperUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetServerForDeveloperForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetServerForDeveloperNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetServerForDeveloperTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{rid}] getServerForDeveloper", response, response.Code())
	}
}

// NewGetServerForDeveloperOK creates a GetServerForDeveloperOK with default headers values
func NewGetServerForDeveloperOK() *GetServerForDeveloperOK {
	return &GetServerForDeveloperOK{}
}

/*
GetServerForDeveloperOK describes a response with status code 200, with default header values.

Get developer server with scopes
*/
type GetServerForDeveloperOK struct {
	Payload *models.GetServerWithScopesDeveloperResponse
}

// IsSuccess returns true when this get server for developer o k response has a 2xx status code
func (o *GetServerForDeveloperOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get server for developer o k response has a 3xx status code
func (o *GetServerForDeveloperOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get server for developer o k response has a 4xx status code
func (o *GetServerForDeveloperOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get server for developer o k response has a 5xx status code
func (o *GetServerForDeveloperOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get server for developer o k response a status code equal to that given
func (o *GetServerForDeveloperOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get server for developer o k response
func (o *GetServerForDeveloperOK) Code() int {
	return 200
}

func (o *GetServerForDeveloperOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperOK %s", 200, payload)
}

func (o *GetServerForDeveloperOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperOK %s", 200, payload)
}

func (o *GetServerForDeveloperOK) GetPayload() *models.GetServerWithScopesDeveloperResponse {
	return o.Payload
}

func (o *GetServerForDeveloperOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetServerWithScopesDeveloperResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetServerForDeveloperUnauthorized creates a GetServerForDeveloperUnauthorized with default headers values
func NewGetServerForDeveloperUnauthorized() *GetServerForDeveloperUnauthorized {
	return &GetServerForDeveloperUnauthorized{}
}

/*
GetServerForDeveloperUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetServerForDeveloperUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get server for developer unauthorized response has a 2xx status code
func (o *GetServerForDeveloperUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get server for developer unauthorized response has a 3xx status code
func (o *GetServerForDeveloperUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get server for developer unauthorized response has a 4xx status code
func (o *GetServerForDeveloperUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get server for developer unauthorized response has a 5xx status code
func (o *GetServerForDeveloperUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get server for developer unauthorized response a status code equal to that given
func (o *GetServerForDeveloperUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get server for developer unauthorized response
func (o *GetServerForDeveloperUnauthorized) Code() int {
	return 401
}

func (o *GetServerForDeveloperUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperUnauthorized %s", 401, payload)
}

func (o *GetServerForDeveloperUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperUnauthorized %s", 401, payload)
}

func (o *GetServerForDeveloperUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetServerForDeveloperUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetServerForDeveloperForbidden creates a GetServerForDeveloperForbidden with default headers values
func NewGetServerForDeveloperForbidden() *GetServerForDeveloperForbidden {
	return &GetServerForDeveloperForbidden{}
}

/*
GetServerForDeveloperForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetServerForDeveloperForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get server for developer forbidden response has a 2xx status code
func (o *GetServerForDeveloperForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get server for developer forbidden response has a 3xx status code
func (o *GetServerForDeveloperForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get server for developer forbidden response has a 4xx status code
func (o *GetServerForDeveloperForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get server for developer forbidden response has a 5xx status code
func (o *GetServerForDeveloperForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get server for developer forbidden response a status code equal to that given
func (o *GetServerForDeveloperForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get server for developer forbidden response
func (o *GetServerForDeveloperForbidden) Code() int {
	return 403
}

func (o *GetServerForDeveloperForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperForbidden %s", 403, payload)
}

func (o *GetServerForDeveloperForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperForbidden %s", 403, payload)
}

func (o *GetServerForDeveloperForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetServerForDeveloperForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetServerForDeveloperNotFound creates a GetServerForDeveloperNotFound with default headers values
func NewGetServerForDeveloperNotFound() *GetServerForDeveloperNotFound {
	return &GetServerForDeveloperNotFound{}
}

/*
GetServerForDeveloperNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetServerForDeveloperNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get server for developer not found response has a 2xx status code
func (o *GetServerForDeveloperNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get server for developer not found response has a 3xx status code
func (o *GetServerForDeveloperNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get server for developer not found response has a 4xx status code
func (o *GetServerForDeveloperNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get server for developer not found response has a 5xx status code
func (o *GetServerForDeveloperNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get server for developer not found response a status code equal to that given
func (o *GetServerForDeveloperNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get server for developer not found response
func (o *GetServerForDeveloperNotFound) Code() int {
	return 404
}

func (o *GetServerForDeveloperNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperNotFound %s", 404, payload)
}

func (o *GetServerForDeveloperNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperNotFound %s", 404, payload)
}

func (o *GetServerForDeveloperNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetServerForDeveloperNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetServerForDeveloperTooManyRequests creates a GetServerForDeveloperTooManyRequests with default headers values
func NewGetServerForDeveloperTooManyRequests() *GetServerForDeveloperTooManyRequests {
	return &GetServerForDeveloperTooManyRequests{}
}

/*
GetServerForDeveloperTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetServerForDeveloperTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get server for developer too many requests response has a 2xx status code
func (o *GetServerForDeveloperTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get server for developer too many requests response has a 3xx status code
func (o *GetServerForDeveloperTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get server for developer too many requests response has a 4xx status code
func (o *GetServerForDeveloperTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get server for developer too many requests response has a 5xx status code
func (o *GetServerForDeveloperTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get server for developer too many requests response a status code equal to that given
func (o *GetServerForDeveloperTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get server for developer too many requests response
func (o *GetServerForDeveloperTooManyRequests) Code() int {
	return 429
}

func (o *GetServerForDeveloperTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperTooManyRequests %s", 429, payload)
}

func (o *GetServerForDeveloperTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{rid}][%d] getServerForDeveloperTooManyRequests %s", 429, payload)
}

func (o *GetServerForDeveloperTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetServerForDeveloperTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
