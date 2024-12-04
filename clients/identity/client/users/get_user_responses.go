// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// GetUserReader is a Reader for the GetUser structure.
type GetUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /admin/pools/{ipID}/users/{userID}] getUser", response, response.Code())
	}
}

// NewGetUserOK creates a GetUserOK with default headers values
func NewGetUserOK() *GetUserOK {
	return &GetUserOK{}
}

/*
GetUserOK describes a response with status code 200, with default header values.

User
*/
type GetUserOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserWithData
}

// IsSuccess returns true when this get user o k response has a 2xx status code
func (o *GetUserOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get user o k response has a 3xx status code
func (o *GetUserOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user o k response has a 4xx status code
func (o *GetUserOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get user o k response has a 5xx status code
func (o *GetUserOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get user o k response a status code equal to that given
func (o *GetUserOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get user o k response
func (o *GetUserOK) Code() int {
	return 200
}

func (o *GetUserOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserOK %s", 200, payload)
}

func (o *GetUserOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserOK %s", 200, payload)
}

func (o *GetUserOK) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *GetUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserUnauthorized creates a GetUserUnauthorized with default headers values
func NewGetUserUnauthorized() *GetUserUnauthorized {
	return &GetUserUnauthorized{}
}

/*
GetUserUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetUserUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user unauthorized response has a 2xx status code
func (o *GetUserUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user unauthorized response has a 3xx status code
func (o *GetUserUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user unauthorized response has a 4xx status code
func (o *GetUserUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user unauthorized response has a 5xx status code
func (o *GetUserUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get user unauthorized response a status code equal to that given
func (o *GetUserUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get user unauthorized response
func (o *GetUserUnauthorized) Code() int {
	return 401
}

func (o *GetUserUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserUnauthorized %s", 401, payload)
}

func (o *GetUserUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserUnauthorized %s", 401, payload)
}

func (o *GetUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserForbidden creates a GetUserForbidden with default headers values
func NewGetUserForbidden() *GetUserForbidden {
	return &GetUserForbidden{}
}

/*
GetUserForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetUserForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user forbidden response has a 2xx status code
func (o *GetUserForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user forbidden response has a 3xx status code
func (o *GetUserForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user forbidden response has a 4xx status code
func (o *GetUserForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user forbidden response has a 5xx status code
func (o *GetUserForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get user forbidden response a status code equal to that given
func (o *GetUserForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get user forbidden response
func (o *GetUserForbidden) Code() int {
	return 403
}

func (o *GetUserForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserForbidden %s", 403, payload)
}

func (o *GetUserForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserForbidden %s", 403, payload)
}

func (o *GetUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserNotFound creates a GetUserNotFound with default headers values
func NewGetUserNotFound() *GetUserNotFound {
	return &GetUserNotFound{}
}

/*
GetUserNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetUserNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user not found response has a 2xx status code
func (o *GetUserNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user not found response has a 3xx status code
func (o *GetUserNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user not found response has a 4xx status code
func (o *GetUserNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user not found response has a 5xx status code
func (o *GetUserNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get user not found response a status code equal to that given
func (o *GetUserNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get user not found response
func (o *GetUserNotFound) Code() int {
	return 404
}

func (o *GetUserNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserNotFound %s", 404, payload)
}

func (o *GetUserNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserNotFound %s", 404, payload)
}

func (o *GetUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserTooManyRequests creates a GetUserTooManyRequests with default headers values
func NewGetUserTooManyRequests() *GetUserTooManyRequests {
	return &GetUserTooManyRequests{}
}

/*
GetUserTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetUserTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user too many requests response has a 2xx status code
func (o *GetUserTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user too many requests response has a 3xx status code
func (o *GetUserTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user too many requests response has a 4xx status code
func (o *GetUserTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user too many requests response has a 5xx status code
func (o *GetUserTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get user too many requests response a status code equal to that given
func (o *GetUserTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get user too many requests response
func (o *GetUserTooManyRequests) Code() int {
	return 429
}

func (o *GetUserTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserTooManyRequests %s", 429, payload)
}

func (o *GetUserTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /admin/pools/{ipID}/users/{userID}][%d] getUserTooManyRequests %s", 429, payload)
}

func (o *GetUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
