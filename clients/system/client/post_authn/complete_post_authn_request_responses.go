// Code generated by go-swagger; DO NOT EDIT.

package post_authn

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// CompletePostAuthnRequestReader is a Reader for the CompletePostAuthnRequest structure.
type CompletePostAuthnRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CompletePostAuthnRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCompletePostAuthnRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewCompletePostAuthnRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCompletePostAuthnRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCompletePostAuthnRequestNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCompletePostAuthnRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /post-authn/{login}/complete] completePostAuthnRequest", response, response.Code())
	}
}

// NewCompletePostAuthnRequestOK creates a CompletePostAuthnRequestOK with default headers values
func NewCompletePostAuthnRequestOK() *CompletePostAuthnRequestOK {
	return &CompletePostAuthnRequestOK{}
}

/*
CompletePostAuthnRequestOK describes a response with status code 200, with default header values.

PostAuthn completeed
*/
type CompletePostAuthnRequestOK struct {
	Payload *models.PostAuthnCompleted
}

// IsSuccess returns true when this complete post authn request o k response has a 2xx status code
func (o *CompletePostAuthnRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this complete post authn request o k response has a 3xx status code
func (o *CompletePostAuthnRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete post authn request o k response has a 4xx status code
func (o *CompletePostAuthnRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this complete post authn request o k response has a 5xx status code
func (o *CompletePostAuthnRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this complete post authn request o k response a status code equal to that given
func (o *CompletePostAuthnRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the complete post authn request o k response
func (o *CompletePostAuthnRequestOK) Code() int {
	return 200
}

func (o *CompletePostAuthnRequestOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestOK %s", 200, payload)
}

func (o *CompletePostAuthnRequestOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestOK %s", 200, payload)
}

func (o *CompletePostAuthnRequestOK) GetPayload() *models.PostAuthnCompleted {
	return o.Payload
}

func (o *CompletePostAuthnRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PostAuthnCompleted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompletePostAuthnRequestUnauthorized creates a CompletePostAuthnRequestUnauthorized with default headers values
func NewCompletePostAuthnRequestUnauthorized() *CompletePostAuthnRequestUnauthorized {
	return &CompletePostAuthnRequestUnauthorized{}
}

/*
CompletePostAuthnRequestUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CompletePostAuthnRequestUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete post authn request unauthorized response has a 2xx status code
func (o *CompletePostAuthnRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete post authn request unauthorized response has a 3xx status code
func (o *CompletePostAuthnRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete post authn request unauthorized response has a 4xx status code
func (o *CompletePostAuthnRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete post authn request unauthorized response has a 5xx status code
func (o *CompletePostAuthnRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this complete post authn request unauthorized response a status code equal to that given
func (o *CompletePostAuthnRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the complete post authn request unauthorized response
func (o *CompletePostAuthnRequestUnauthorized) Code() int {
	return 401
}

func (o *CompletePostAuthnRequestUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestUnauthorized %s", 401, payload)
}

func (o *CompletePostAuthnRequestUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestUnauthorized %s", 401, payload)
}

func (o *CompletePostAuthnRequestUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompletePostAuthnRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompletePostAuthnRequestForbidden creates a CompletePostAuthnRequestForbidden with default headers values
func NewCompletePostAuthnRequestForbidden() *CompletePostAuthnRequestForbidden {
	return &CompletePostAuthnRequestForbidden{}
}

/*
CompletePostAuthnRequestForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CompletePostAuthnRequestForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete post authn request forbidden response has a 2xx status code
func (o *CompletePostAuthnRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete post authn request forbidden response has a 3xx status code
func (o *CompletePostAuthnRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete post authn request forbidden response has a 4xx status code
func (o *CompletePostAuthnRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete post authn request forbidden response has a 5xx status code
func (o *CompletePostAuthnRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this complete post authn request forbidden response a status code equal to that given
func (o *CompletePostAuthnRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the complete post authn request forbidden response
func (o *CompletePostAuthnRequestForbidden) Code() int {
	return 403
}

func (o *CompletePostAuthnRequestForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestForbidden %s", 403, payload)
}

func (o *CompletePostAuthnRequestForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestForbidden %s", 403, payload)
}

func (o *CompletePostAuthnRequestForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompletePostAuthnRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompletePostAuthnRequestNotFound creates a CompletePostAuthnRequestNotFound with default headers values
func NewCompletePostAuthnRequestNotFound() *CompletePostAuthnRequestNotFound {
	return &CompletePostAuthnRequestNotFound{}
}

/*
CompletePostAuthnRequestNotFound describes a response with status code 404, with default header values.

Not found
*/
type CompletePostAuthnRequestNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete post authn request not found response has a 2xx status code
func (o *CompletePostAuthnRequestNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete post authn request not found response has a 3xx status code
func (o *CompletePostAuthnRequestNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete post authn request not found response has a 4xx status code
func (o *CompletePostAuthnRequestNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete post authn request not found response has a 5xx status code
func (o *CompletePostAuthnRequestNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this complete post authn request not found response a status code equal to that given
func (o *CompletePostAuthnRequestNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the complete post authn request not found response
func (o *CompletePostAuthnRequestNotFound) Code() int {
	return 404
}

func (o *CompletePostAuthnRequestNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestNotFound %s", 404, payload)
}

func (o *CompletePostAuthnRequestNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestNotFound %s", 404, payload)
}

func (o *CompletePostAuthnRequestNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompletePostAuthnRequestNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompletePostAuthnRequestTooManyRequests creates a CompletePostAuthnRequestTooManyRequests with default headers values
func NewCompletePostAuthnRequestTooManyRequests() *CompletePostAuthnRequestTooManyRequests {
	return &CompletePostAuthnRequestTooManyRequests{}
}

/*
CompletePostAuthnRequestTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CompletePostAuthnRequestTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete post authn request too many requests response has a 2xx status code
func (o *CompletePostAuthnRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete post authn request too many requests response has a 3xx status code
func (o *CompletePostAuthnRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete post authn request too many requests response has a 4xx status code
func (o *CompletePostAuthnRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete post authn request too many requests response has a 5xx status code
func (o *CompletePostAuthnRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this complete post authn request too many requests response a status code equal to that given
func (o *CompletePostAuthnRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the complete post authn request too many requests response
func (o *CompletePostAuthnRequestTooManyRequests) Code() int {
	return 429
}

func (o *CompletePostAuthnRequestTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestTooManyRequests %s", 429, payload)
}

func (o *CompletePostAuthnRequestTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/complete][%d] completePostAuthnRequestTooManyRequests %s", 429, payload)
}

func (o *CompletePostAuthnRequestTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompletePostAuthnRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
