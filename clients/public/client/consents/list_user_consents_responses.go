// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/public/models"
)

// ListUserConsentsReader is a Reader for the ListUserConsents structure.
type ListUserConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListUserConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListUserConsentsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListUserConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListUserConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListUserConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListUserConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /privacy/consents] listUserConsents", response, response.Code())
	}
}

// NewListUserConsentsOK creates a ListUserConsentsOK with default headers values
func NewListUserConsentsOK() *ListUserConsentsOK {
	return &ListUserConsentsOK{}
}

/*
ListUserConsentsOK describes a response with status code 200, with default header values.

Consents with grants
*/
type ListUserConsentsOK struct {
	Payload *models.ConsentsWithGrants
}

// IsSuccess returns true when this list user consents o k response has a 2xx status code
func (o *ListUserConsentsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list user consents o k response has a 3xx status code
func (o *ListUserConsentsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user consents o k response has a 4xx status code
func (o *ListUserConsentsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list user consents o k response has a 5xx status code
func (o *ListUserConsentsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list user consents o k response a status code equal to that given
func (o *ListUserConsentsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list user consents o k response
func (o *ListUserConsentsOK) Code() int {
	return 200
}

func (o *ListUserConsentsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsOK %s", 200, payload)
}

func (o *ListUserConsentsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsOK %s", 200, payload)
}

func (o *ListUserConsentsOK) GetPayload() *models.ConsentsWithGrants {
	return o.Payload
}

func (o *ListUserConsentsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentsWithGrants)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserConsentsUnauthorized creates a ListUserConsentsUnauthorized with default headers values
func NewListUserConsentsUnauthorized() *ListUserConsentsUnauthorized {
	return &ListUserConsentsUnauthorized{}
}

/*
ListUserConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListUserConsentsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user consents unauthorized response has a 2xx status code
func (o *ListUserConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user consents unauthorized response has a 3xx status code
func (o *ListUserConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user consents unauthorized response has a 4xx status code
func (o *ListUserConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user consents unauthorized response has a 5xx status code
func (o *ListUserConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list user consents unauthorized response a status code equal to that given
func (o *ListUserConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list user consents unauthorized response
func (o *ListUserConsentsUnauthorized) Code() int {
	return 401
}

func (o *ListUserConsentsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsUnauthorized %s", 401, payload)
}

func (o *ListUserConsentsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsUnauthorized %s", 401, payload)
}

func (o *ListUserConsentsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserConsentsForbidden creates a ListUserConsentsForbidden with default headers values
func NewListUserConsentsForbidden() *ListUserConsentsForbidden {
	return &ListUserConsentsForbidden{}
}

/*
ListUserConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListUserConsentsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user consents forbidden response has a 2xx status code
func (o *ListUserConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user consents forbidden response has a 3xx status code
func (o *ListUserConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user consents forbidden response has a 4xx status code
func (o *ListUserConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user consents forbidden response has a 5xx status code
func (o *ListUserConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list user consents forbidden response a status code equal to that given
func (o *ListUserConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list user consents forbidden response
func (o *ListUserConsentsForbidden) Code() int {
	return 403
}

func (o *ListUserConsentsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsForbidden %s", 403, payload)
}

func (o *ListUserConsentsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsForbidden %s", 403, payload)
}

func (o *ListUserConsentsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserConsentsNotFound creates a ListUserConsentsNotFound with default headers values
func NewListUserConsentsNotFound() *ListUserConsentsNotFound {
	return &ListUserConsentsNotFound{}
}

/*
ListUserConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListUserConsentsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user consents not found response has a 2xx status code
func (o *ListUserConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user consents not found response has a 3xx status code
func (o *ListUserConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user consents not found response has a 4xx status code
func (o *ListUserConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user consents not found response has a 5xx status code
func (o *ListUserConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list user consents not found response a status code equal to that given
func (o *ListUserConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list user consents not found response
func (o *ListUserConsentsNotFound) Code() int {
	return 404
}

func (o *ListUserConsentsNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsNotFound %s", 404, payload)
}

func (o *ListUserConsentsNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsNotFound %s", 404, payload)
}

func (o *ListUserConsentsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserConsentsTooManyRequests creates a ListUserConsentsTooManyRequests with default headers values
func NewListUserConsentsTooManyRequests() *ListUserConsentsTooManyRequests {
	return &ListUserConsentsTooManyRequests{}
}

/*
ListUserConsentsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListUserConsentsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user consents too many requests response has a 2xx status code
func (o *ListUserConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user consents too many requests response has a 3xx status code
func (o *ListUserConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user consents too many requests response has a 4xx status code
func (o *ListUserConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user consents too many requests response has a 5xx status code
func (o *ListUserConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list user consents too many requests response a status code equal to that given
func (o *ListUserConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list user consents too many requests response
func (o *ListUserConsentsTooManyRequests) Code() int {
	return 429
}

func (o *ListUserConsentsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsTooManyRequests %s", 429, payload)
}

func (o *ListUserConsentsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /privacy/consents][%d] listUserConsentsTooManyRequests %s", 429, payload)
}

func (o *ListUserConsentsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
