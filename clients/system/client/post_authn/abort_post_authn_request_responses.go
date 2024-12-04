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

// AbortPostAuthnRequestReader is a Reader for the AbortPostAuthnRequest structure.
type AbortPostAuthnRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AbortPostAuthnRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAbortPostAuthnRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAbortPostAuthnRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAbortPostAuthnRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAbortPostAuthnRequestNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAbortPostAuthnRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /post-authn/{login}/abort] abortPostAuthnRequest", response, response.Code())
	}
}

// NewAbortPostAuthnRequestOK creates a AbortPostAuthnRequestOK with default headers values
func NewAbortPostAuthnRequestOK() *AbortPostAuthnRequestOK {
	return &AbortPostAuthnRequestOK{}
}

/*
AbortPostAuthnRequestOK describes a response with status code 200, with default header values.

Login aborted
*/
type AbortPostAuthnRequestOK struct {
	Payload *models.PostAuthnAborted
}

// IsSuccess returns true when this abort post authn request o k response has a 2xx status code
func (o *AbortPostAuthnRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this abort post authn request o k response has a 3xx status code
func (o *AbortPostAuthnRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this abort post authn request o k response has a 4xx status code
func (o *AbortPostAuthnRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this abort post authn request o k response has a 5xx status code
func (o *AbortPostAuthnRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this abort post authn request o k response a status code equal to that given
func (o *AbortPostAuthnRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the abort post authn request o k response
func (o *AbortPostAuthnRequestOK) Code() int {
	return 200
}

func (o *AbortPostAuthnRequestOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestOK %s", 200, payload)
}

func (o *AbortPostAuthnRequestOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestOK %s", 200, payload)
}

func (o *AbortPostAuthnRequestOK) GetPayload() *models.PostAuthnAborted {
	return o.Payload
}

func (o *AbortPostAuthnRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PostAuthnAborted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAbortPostAuthnRequestUnauthorized creates a AbortPostAuthnRequestUnauthorized with default headers values
func NewAbortPostAuthnRequestUnauthorized() *AbortPostAuthnRequestUnauthorized {
	return &AbortPostAuthnRequestUnauthorized{}
}

/*
AbortPostAuthnRequestUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AbortPostAuthnRequestUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this abort post authn request unauthorized response has a 2xx status code
func (o *AbortPostAuthnRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this abort post authn request unauthorized response has a 3xx status code
func (o *AbortPostAuthnRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this abort post authn request unauthorized response has a 4xx status code
func (o *AbortPostAuthnRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this abort post authn request unauthorized response has a 5xx status code
func (o *AbortPostAuthnRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this abort post authn request unauthorized response a status code equal to that given
func (o *AbortPostAuthnRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the abort post authn request unauthorized response
func (o *AbortPostAuthnRequestUnauthorized) Code() int {
	return 401
}

func (o *AbortPostAuthnRequestUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestUnauthorized %s", 401, payload)
}

func (o *AbortPostAuthnRequestUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestUnauthorized %s", 401, payload)
}

func (o *AbortPostAuthnRequestUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AbortPostAuthnRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAbortPostAuthnRequestForbidden creates a AbortPostAuthnRequestForbidden with default headers values
func NewAbortPostAuthnRequestForbidden() *AbortPostAuthnRequestForbidden {
	return &AbortPostAuthnRequestForbidden{}
}

/*
AbortPostAuthnRequestForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AbortPostAuthnRequestForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this abort post authn request forbidden response has a 2xx status code
func (o *AbortPostAuthnRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this abort post authn request forbidden response has a 3xx status code
func (o *AbortPostAuthnRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this abort post authn request forbidden response has a 4xx status code
func (o *AbortPostAuthnRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this abort post authn request forbidden response has a 5xx status code
func (o *AbortPostAuthnRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this abort post authn request forbidden response a status code equal to that given
func (o *AbortPostAuthnRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the abort post authn request forbidden response
func (o *AbortPostAuthnRequestForbidden) Code() int {
	return 403
}

func (o *AbortPostAuthnRequestForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestForbidden %s", 403, payload)
}

func (o *AbortPostAuthnRequestForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestForbidden %s", 403, payload)
}

func (o *AbortPostAuthnRequestForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AbortPostAuthnRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAbortPostAuthnRequestNotFound creates a AbortPostAuthnRequestNotFound with default headers values
func NewAbortPostAuthnRequestNotFound() *AbortPostAuthnRequestNotFound {
	return &AbortPostAuthnRequestNotFound{}
}

/*
AbortPostAuthnRequestNotFound describes a response with status code 404, with default header values.

Not found
*/
type AbortPostAuthnRequestNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this abort post authn request not found response has a 2xx status code
func (o *AbortPostAuthnRequestNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this abort post authn request not found response has a 3xx status code
func (o *AbortPostAuthnRequestNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this abort post authn request not found response has a 4xx status code
func (o *AbortPostAuthnRequestNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this abort post authn request not found response has a 5xx status code
func (o *AbortPostAuthnRequestNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this abort post authn request not found response a status code equal to that given
func (o *AbortPostAuthnRequestNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the abort post authn request not found response
func (o *AbortPostAuthnRequestNotFound) Code() int {
	return 404
}

func (o *AbortPostAuthnRequestNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestNotFound %s", 404, payload)
}

func (o *AbortPostAuthnRequestNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestNotFound %s", 404, payload)
}

func (o *AbortPostAuthnRequestNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AbortPostAuthnRequestNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAbortPostAuthnRequestTooManyRequests creates a AbortPostAuthnRequestTooManyRequests with default headers values
func NewAbortPostAuthnRequestTooManyRequests() *AbortPostAuthnRequestTooManyRequests {
	return &AbortPostAuthnRequestTooManyRequests{}
}

/*
AbortPostAuthnRequestTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type AbortPostAuthnRequestTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this abort post authn request too many requests response has a 2xx status code
func (o *AbortPostAuthnRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this abort post authn request too many requests response has a 3xx status code
func (o *AbortPostAuthnRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this abort post authn request too many requests response has a 4xx status code
func (o *AbortPostAuthnRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this abort post authn request too many requests response has a 5xx status code
func (o *AbortPostAuthnRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this abort post authn request too many requests response a status code equal to that given
func (o *AbortPostAuthnRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the abort post authn request too many requests response
func (o *AbortPostAuthnRequestTooManyRequests) Code() int {
	return 429
}

func (o *AbortPostAuthnRequestTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestTooManyRequests %s", 429, payload)
}

func (o *AbortPostAuthnRequestTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /post-authn/{login}/abort][%d] abortPostAuthnRequestTooManyRequests %s", 429, payload)
}

func (o *AbortPostAuthnRequestTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *AbortPostAuthnRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
