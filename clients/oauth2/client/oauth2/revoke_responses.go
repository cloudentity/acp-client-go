// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/oauth2/models"
)

// RevokeReader is a Reader for the Revoke structure.
type RevokeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRevokeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /oauth2/revoke] revoke", response, response.Code())
	}
}

// NewRevokeOK creates a RevokeOK with default headers values
func NewRevokeOK() *RevokeOK {
	return &RevokeOK{}
}

/*
RevokeOK describes a response with status code 200, with default header values.

Empty response
*/
type RevokeOK struct {
}

// IsSuccess returns true when this revoke o k response has a 2xx status code
func (o *RevokeOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke o k response has a 3xx status code
func (o *RevokeOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke o k response has a 4xx status code
func (o *RevokeOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke o k response has a 5xx status code
func (o *RevokeOK) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke o k response a status code equal to that given
func (o *RevokeOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the revoke o k response
func (o *RevokeOK) Code() int {
	return 200
}

func (o *RevokeOK) Error() string {
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeOK", 200)
}

func (o *RevokeOK) String() string {
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeOK", 200)
}

func (o *RevokeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeUnauthorized creates a RevokeUnauthorized with default headers values
func NewRevokeUnauthorized() *RevokeUnauthorized {
	return &RevokeUnauthorized{}
}

/*
RevokeUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type RevokeUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this revoke unauthorized response has a 2xx status code
func (o *RevokeUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke unauthorized response has a 3xx status code
func (o *RevokeUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke unauthorized response has a 4xx status code
func (o *RevokeUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke unauthorized response has a 5xx status code
func (o *RevokeUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke unauthorized response a status code equal to that given
func (o *RevokeUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke unauthorized response
func (o *RevokeUnauthorized) Code() int {
	return 401
}

func (o *RevokeUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeUnauthorized %s", 401, payload)
}

func (o *RevokeUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeUnauthorized %s", 401, payload)
}

func (o *RevokeUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RevokeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeNotFound creates a RevokeNotFound with default headers values
func NewRevokeNotFound() *RevokeNotFound {
	return &RevokeNotFound{}
}

/*
RevokeNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type RevokeNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this revoke not found response has a 2xx status code
func (o *RevokeNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke not found response has a 3xx status code
func (o *RevokeNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke not found response has a 4xx status code
func (o *RevokeNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke not found response has a 5xx status code
func (o *RevokeNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke not found response a status code equal to that given
func (o *RevokeNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke not found response
func (o *RevokeNotFound) Code() int {
	return 404
}

func (o *RevokeNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeNotFound %s", 404, payload)
}

func (o *RevokeNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeNotFound %s", 404, payload)
}

func (o *RevokeNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RevokeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeTooManyRequests creates a RevokeTooManyRequests with default headers values
func NewRevokeTooManyRequests() *RevokeTooManyRequests {
	return &RevokeTooManyRequests{}
}

/*
RevokeTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type RevokeTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this revoke too many requests response has a 2xx status code
func (o *RevokeTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke too many requests response has a 3xx status code
func (o *RevokeTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke too many requests response has a 4xx status code
func (o *RevokeTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke too many requests response has a 5xx status code
func (o *RevokeTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke too many requests response a status code equal to that given
func (o *RevokeTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the revoke too many requests response
func (o *RevokeTooManyRequests) Code() int {
	return 429
}

func (o *RevokeTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeTooManyRequests %s", 429, payload)
}

func (o *RevokeTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /oauth2/revoke][%d] revokeTooManyRequests %s", 429, payload)
}

func (o *RevokeTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *RevokeTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
