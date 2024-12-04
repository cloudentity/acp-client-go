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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetAuthorizationServerReader is a Reader for the GetAuthorizationServer structure.
type GetAuthorizationServerReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAuthorizationServerReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAuthorizationServerOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAuthorizationServerUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAuthorizationServerForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAuthorizationServerNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAuthorizationServerTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}] getAuthorizationServer", response, response.Code())
	}
}

// NewGetAuthorizationServerOK creates a GetAuthorizationServerOK with default headers values
func NewGetAuthorizationServerOK() *GetAuthorizationServerOK {
	return &GetAuthorizationServerOK{}
}

/*
GetAuthorizationServerOK describes a response with status code 200, with default header values.

Server
*/
type GetAuthorizationServerOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServerResponse
}

// IsSuccess returns true when this get authorization server o k response has a 2xx status code
func (o *GetAuthorizationServerOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get authorization server o k response has a 3xx status code
func (o *GetAuthorizationServerOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authorization server o k response has a 4xx status code
func (o *GetAuthorizationServerOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get authorization server o k response has a 5xx status code
func (o *GetAuthorizationServerOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get authorization server o k response a status code equal to that given
func (o *GetAuthorizationServerOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get authorization server o k response
func (o *GetAuthorizationServerOK) Code() int {
	return 200
}

func (o *GetAuthorizationServerOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerOK %s", 200, payload)
}

func (o *GetAuthorizationServerOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerOK %s", 200, payload)
}

func (o *GetAuthorizationServerOK) GetPayload() *models.ServerResponse {
	return o.Payload
}

func (o *GetAuthorizationServerOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServerResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuthorizationServerUnauthorized creates a GetAuthorizationServerUnauthorized with default headers values
func NewGetAuthorizationServerUnauthorized() *GetAuthorizationServerUnauthorized {
	return &GetAuthorizationServerUnauthorized{}
}

/*
GetAuthorizationServerUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAuthorizationServerUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get authorization server unauthorized response has a 2xx status code
func (o *GetAuthorizationServerUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get authorization server unauthorized response has a 3xx status code
func (o *GetAuthorizationServerUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authorization server unauthorized response has a 4xx status code
func (o *GetAuthorizationServerUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get authorization server unauthorized response has a 5xx status code
func (o *GetAuthorizationServerUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get authorization server unauthorized response a status code equal to that given
func (o *GetAuthorizationServerUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get authorization server unauthorized response
func (o *GetAuthorizationServerUnauthorized) Code() int {
	return 401
}

func (o *GetAuthorizationServerUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerUnauthorized %s", 401, payload)
}

func (o *GetAuthorizationServerUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerUnauthorized %s", 401, payload)
}

func (o *GetAuthorizationServerUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuthorizationServerUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuthorizationServerForbidden creates a GetAuthorizationServerForbidden with default headers values
func NewGetAuthorizationServerForbidden() *GetAuthorizationServerForbidden {
	return &GetAuthorizationServerForbidden{}
}

/*
GetAuthorizationServerForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAuthorizationServerForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get authorization server forbidden response has a 2xx status code
func (o *GetAuthorizationServerForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get authorization server forbidden response has a 3xx status code
func (o *GetAuthorizationServerForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authorization server forbidden response has a 4xx status code
func (o *GetAuthorizationServerForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get authorization server forbidden response has a 5xx status code
func (o *GetAuthorizationServerForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get authorization server forbidden response a status code equal to that given
func (o *GetAuthorizationServerForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get authorization server forbidden response
func (o *GetAuthorizationServerForbidden) Code() int {
	return 403
}

func (o *GetAuthorizationServerForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerForbidden %s", 403, payload)
}

func (o *GetAuthorizationServerForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerForbidden %s", 403, payload)
}

func (o *GetAuthorizationServerForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuthorizationServerForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuthorizationServerNotFound creates a GetAuthorizationServerNotFound with default headers values
func NewGetAuthorizationServerNotFound() *GetAuthorizationServerNotFound {
	return &GetAuthorizationServerNotFound{}
}

/*
GetAuthorizationServerNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAuthorizationServerNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get authorization server not found response has a 2xx status code
func (o *GetAuthorizationServerNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get authorization server not found response has a 3xx status code
func (o *GetAuthorizationServerNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authorization server not found response has a 4xx status code
func (o *GetAuthorizationServerNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get authorization server not found response has a 5xx status code
func (o *GetAuthorizationServerNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get authorization server not found response a status code equal to that given
func (o *GetAuthorizationServerNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get authorization server not found response
func (o *GetAuthorizationServerNotFound) Code() int {
	return 404
}

func (o *GetAuthorizationServerNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerNotFound %s", 404, payload)
}

func (o *GetAuthorizationServerNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerNotFound %s", 404, payload)
}

func (o *GetAuthorizationServerNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuthorizationServerNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuthorizationServerTooManyRequests creates a GetAuthorizationServerTooManyRequests with default headers values
func NewGetAuthorizationServerTooManyRequests() *GetAuthorizationServerTooManyRequests {
	return &GetAuthorizationServerTooManyRequests{}
}

/*
GetAuthorizationServerTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetAuthorizationServerTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get authorization server too many requests response has a 2xx status code
func (o *GetAuthorizationServerTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get authorization server too many requests response has a 3xx status code
func (o *GetAuthorizationServerTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get authorization server too many requests response has a 4xx status code
func (o *GetAuthorizationServerTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get authorization server too many requests response has a 5xx status code
func (o *GetAuthorizationServerTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get authorization server too many requests response a status code equal to that given
func (o *GetAuthorizationServerTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get authorization server too many requests response
func (o *GetAuthorizationServerTooManyRequests) Code() int {
	return 429
}

func (o *GetAuthorizationServerTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerTooManyRequests %s", 429, payload)
}

func (o *GetAuthorizationServerTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}][%d] getAuthorizationServerTooManyRequests %s", 429, payload)
}

func (o *GetAuthorizationServerTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuthorizationServerTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
