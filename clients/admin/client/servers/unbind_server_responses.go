// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UnbindServerReader is a Reader for the UnbindServer structure.
type UnbindServerReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UnbindServerReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUnbindServerOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUnbindServerUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUnbindServerForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUnbindServerNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUnbindServerTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /servers/{wid}/unbind/{rid}] unbindServer", response, response.Code())
	}
}

// NewUnbindServerOK creates a UnbindServerOK with default headers values
func NewUnbindServerOK() *UnbindServerOK {
	return &UnbindServerOK{}
}

/*
UnbindServerOK describes a response with status code 200, with default header values.

Server to server binding
*/
type UnbindServerOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServerToServer
}

// IsSuccess returns true when this unbind server o k response has a 2xx status code
func (o *UnbindServerOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this unbind server o k response has a 3xx status code
func (o *UnbindServerOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind server o k response has a 4xx status code
func (o *UnbindServerOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this unbind server o k response has a 5xx status code
func (o *UnbindServerOK) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind server o k response a status code equal to that given
func (o *UnbindServerOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the unbind server o k response
func (o *UnbindServerOK) Code() int {
	return 200
}

func (o *UnbindServerOK) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerOK  %+v", 200, o.Payload)
}

func (o *UnbindServerOK) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerOK  %+v", 200, o.Payload)
}

func (o *UnbindServerOK) GetPayload() *models.ServerToServer {
	return o.Payload
}

func (o *UnbindServerOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServerToServer)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindServerUnauthorized creates a UnbindServerUnauthorized with default headers values
func NewUnbindServerUnauthorized() *UnbindServerUnauthorized {
	return &UnbindServerUnauthorized{}
}

/*
UnbindServerUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UnbindServerUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind server unauthorized response has a 2xx status code
func (o *UnbindServerUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind server unauthorized response has a 3xx status code
func (o *UnbindServerUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind server unauthorized response has a 4xx status code
func (o *UnbindServerUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind server unauthorized response has a 5xx status code
func (o *UnbindServerUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind server unauthorized response a status code equal to that given
func (o *UnbindServerUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the unbind server unauthorized response
func (o *UnbindServerUnauthorized) Code() int {
	return 401
}

func (o *UnbindServerUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerUnauthorized  %+v", 401, o.Payload)
}

func (o *UnbindServerUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerUnauthorized  %+v", 401, o.Payload)
}

func (o *UnbindServerUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindServerUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindServerForbidden creates a UnbindServerForbidden with default headers values
func NewUnbindServerForbidden() *UnbindServerForbidden {
	return &UnbindServerForbidden{}
}

/*
UnbindServerForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UnbindServerForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind server forbidden response has a 2xx status code
func (o *UnbindServerForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind server forbidden response has a 3xx status code
func (o *UnbindServerForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind server forbidden response has a 4xx status code
func (o *UnbindServerForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind server forbidden response has a 5xx status code
func (o *UnbindServerForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind server forbidden response a status code equal to that given
func (o *UnbindServerForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the unbind server forbidden response
func (o *UnbindServerForbidden) Code() int {
	return 403
}

func (o *UnbindServerForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerForbidden  %+v", 403, o.Payload)
}

func (o *UnbindServerForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerForbidden  %+v", 403, o.Payload)
}

func (o *UnbindServerForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindServerForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindServerNotFound creates a UnbindServerNotFound with default headers values
func NewUnbindServerNotFound() *UnbindServerNotFound {
	return &UnbindServerNotFound{}
}

/*
UnbindServerNotFound describes a response with status code 404, with default header values.

Not found
*/
type UnbindServerNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind server not found response has a 2xx status code
func (o *UnbindServerNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind server not found response has a 3xx status code
func (o *UnbindServerNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind server not found response has a 4xx status code
func (o *UnbindServerNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind server not found response has a 5xx status code
func (o *UnbindServerNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind server not found response a status code equal to that given
func (o *UnbindServerNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the unbind server not found response
func (o *UnbindServerNotFound) Code() int {
	return 404
}

func (o *UnbindServerNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerNotFound  %+v", 404, o.Payload)
}

func (o *UnbindServerNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerNotFound  %+v", 404, o.Payload)
}

func (o *UnbindServerNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindServerNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindServerTooManyRequests creates a UnbindServerTooManyRequests with default headers values
func NewUnbindServerTooManyRequests() *UnbindServerTooManyRequests {
	return &UnbindServerTooManyRequests{}
}

/*
UnbindServerTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UnbindServerTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind server too many requests response has a 2xx status code
func (o *UnbindServerTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind server too many requests response has a 3xx status code
func (o *UnbindServerTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind server too many requests response has a 4xx status code
func (o *UnbindServerTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind server too many requests response has a 5xx status code
func (o *UnbindServerTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind server too many requests response a status code equal to that given
func (o *UnbindServerTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the unbind server too many requests response
func (o *UnbindServerTooManyRequests) Code() int {
	return 429
}

func (o *UnbindServerTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *UnbindServerTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/unbind/{rid}][%d] unbindServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *UnbindServerTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindServerTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
