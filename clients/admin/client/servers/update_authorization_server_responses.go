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

// UpdateAuthorizationServerReader is a Reader for the UpdateAuthorizationServer structure.
type UpdateAuthorizationServerReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAuthorizationServerReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAuthorizationServerOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAuthorizationServerBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAuthorizationServerUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateAuthorizationServerForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAuthorizationServerNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateAuthorizationServerUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateAuthorizationServerTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}] updateAuthorizationServer", response, response.Code())
	}
}

// NewUpdateAuthorizationServerOK creates a UpdateAuthorizationServerOK with default headers values
func NewUpdateAuthorizationServerOK() *UpdateAuthorizationServerOK {
	return &UpdateAuthorizationServerOK{}
}

/*
UpdateAuthorizationServerOK describes a response with status code 200, with default header values.

Server
*/
type UpdateAuthorizationServerOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServerResponse
}

// IsSuccess returns true when this update authorization server o k response has a 2xx status code
func (o *UpdateAuthorizationServerOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update authorization server o k response has a 3xx status code
func (o *UpdateAuthorizationServerOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server o k response has a 4xx status code
func (o *UpdateAuthorizationServerOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update authorization server o k response has a 5xx status code
func (o *UpdateAuthorizationServerOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server o k response a status code equal to that given
func (o *UpdateAuthorizationServerOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update authorization server o k response
func (o *UpdateAuthorizationServerOK) Code() int {
	return 200
}

func (o *UpdateAuthorizationServerOK) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerOK  %+v", 200, o.Payload)
}

func (o *UpdateAuthorizationServerOK) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerOK  %+v", 200, o.Payload)
}

func (o *UpdateAuthorizationServerOK) GetPayload() *models.ServerResponse {
	return o.Payload
}

func (o *UpdateAuthorizationServerOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateAuthorizationServerBadRequest creates a UpdateAuthorizationServerBadRequest with default headers values
func NewUpdateAuthorizationServerBadRequest() *UpdateAuthorizationServerBadRequest {
	return &UpdateAuthorizationServerBadRequest{}
}

/*
UpdateAuthorizationServerBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateAuthorizationServerBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server bad request response has a 2xx status code
func (o *UpdateAuthorizationServerBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server bad request response has a 3xx status code
func (o *UpdateAuthorizationServerBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server bad request response has a 4xx status code
func (o *UpdateAuthorizationServerBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server bad request response has a 5xx status code
func (o *UpdateAuthorizationServerBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server bad request response a status code equal to that given
func (o *UpdateAuthorizationServerBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update authorization server bad request response
func (o *UpdateAuthorizationServerBadRequest) Code() int {
	return 400
}

func (o *UpdateAuthorizationServerBadRequest) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateAuthorizationServerBadRequest) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateAuthorizationServerBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthorizationServerUnauthorized creates a UpdateAuthorizationServerUnauthorized with default headers values
func NewUpdateAuthorizationServerUnauthorized() *UpdateAuthorizationServerUnauthorized {
	return &UpdateAuthorizationServerUnauthorized{}
}

/*
UpdateAuthorizationServerUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateAuthorizationServerUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server unauthorized response has a 2xx status code
func (o *UpdateAuthorizationServerUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server unauthorized response has a 3xx status code
func (o *UpdateAuthorizationServerUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server unauthorized response has a 4xx status code
func (o *UpdateAuthorizationServerUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server unauthorized response has a 5xx status code
func (o *UpdateAuthorizationServerUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server unauthorized response a status code equal to that given
func (o *UpdateAuthorizationServerUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update authorization server unauthorized response
func (o *UpdateAuthorizationServerUnauthorized) Code() int {
	return 401
}

func (o *UpdateAuthorizationServerUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateAuthorizationServerUnauthorized) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateAuthorizationServerUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthorizationServerForbidden creates a UpdateAuthorizationServerForbidden with default headers values
func NewUpdateAuthorizationServerForbidden() *UpdateAuthorizationServerForbidden {
	return &UpdateAuthorizationServerForbidden{}
}

/*
UpdateAuthorizationServerForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateAuthorizationServerForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server forbidden response has a 2xx status code
func (o *UpdateAuthorizationServerForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server forbidden response has a 3xx status code
func (o *UpdateAuthorizationServerForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server forbidden response has a 4xx status code
func (o *UpdateAuthorizationServerForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server forbidden response has a 5xx status code
func (o *UpdateAuthorizationServerForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server forbidden response a status code equal to that given
func (o *UpdateAuthorizationServerForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update authorization server forbidden response
func (o *UpdateAuthorizationServerForbidden) Code() int {
	return 403
}

func (o *UpdateAuthorizationServerForbidden) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerForbidden  %+v", 403, o.Payload)
}

func (o *UpdateAuthorizationServerForbidden) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerForbidden  %+v", 403, o.Payload)
}

func (o *UpdateAuthorizationServerForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthorizationServerNotFound creates a UpdateAuthorizationServerNotFound with default headers values
func NewUpdateAuthorizationServerNotFound() *UpdateAuthorizationServerNotFound {
	return &UpdateAuthorizationServerNotFound{}
}

/*
UpdateAuthorizationServerNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateAuthorizationServerNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server not found response has a 2xx status code
func (o *UpdateAuthorizationServerNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server not found response has a 3xx status code
func (o *UpdateAuthorizationServerNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server not found response has a 4xx status code
func (o *UpdateAuthorizationServerNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server not found response has a 5xx status code
func (o *UpdateAuthorizationServerNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server not found response a status code equal to that given
func (o *UpdateAuthorizationServerNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update authorization server not found response
func (o *UpdateAuthorizationServerNotFound) Code() int {
	return 404
}

func (o *UpdateAuthorizationServerNotFound) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerNotFound  %+v", 404, o.Payload)
}

func (o *UpdateAuthorizationServerNotFound) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerNotFound  %+v", 404, o.Payload)
}

func (o *UpdateAuthorizationServerNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthorizationServerUnprocessableEntity creates a UpdateAuthorizationServerUnprocessableEntity with default headers values
func NewUpdateAuthorizationServerUnprocessableEntity() *UpdateAuthorizationServerUnprocessableEntity {
	return &UpdateAuthorizationServerUnprocessableEntity{}
}

/*
UpdateAuthorizationServerUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateAuthorizationServerUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server unprocessable entity response has a 2xx status code
func (o *UpdateAuthorizationServerUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server unprocessable entity response has a 3xx status code
func (o *UpdateAuthorizationServerUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server unprocessable entity response has a 4xx status code
func (o *UpdateAuthorizationServerUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server unprocessable entity response has a 5xx status code
func (o *UpdateAuthorizationServerUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server unprocessable entity response a status code equal to that given
func (o *UpdateAuthorizationServerUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update authorization server unprocessable entity response
func (o *UpdateAuthorizationServerUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateAuthorizationServerUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateAuthorizationServerUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateAuthorizationServerUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAuthorizationServerTooManyRequests creates a UpdateAuthorizationServerTooManyRequests with default headers values
func NewUpdateAuthorizationServerTooManyRequests() *UpdateAuthorizationServerTooManyRequests {
	return &UpdateAuthorizationServerTooManyRequests{}
}

/*
UpdateAuthorizationServerTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateAuthorizationServerTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update authorization server too many requests response has a 2xx status code
func (o *UpdateAuthorizationServerTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update authorization server too many requests response has a 3xx status code
func (o *UpdateAuthorizationServerTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update authorization server too many requests response has a 4xx status code
func (o *UpdateAuthorizationServerTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update authorization server too many requests response has a 5xx status code
func (o *UpdateAuthorizationServerTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update authorization server too many requests response a status code equal to that given
func (o *UpdateAuthorizationServerTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update authorization server too many requests response
func (o *UpdateAuthorizationServerTooManyRequests) Code() int {
	return 429
}

func (o *UpdateAuthorizationServerTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateAuthorizationServerTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /servers/{wid}][%d] updateAuthorizationServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateAuthorizationServerTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAuthorizationServerTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
