// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identityself/models"
)

// GetUserProfileV2Reader is a Reader for the GetUserProfileV2 structure.
type GetUserProfileV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUserProfileV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUserProfileV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetUserProfileV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetUserProfileV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetUserProfileV2NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetUserProfileV2PreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetUserProfileV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /v2/self/me] getUserProfileV2", response, response.Code())
	}
}

// NewGetUserProfileV2OK creates a GetUserProfileV2OK with default headers values
func NewGetUserProfileV2OK() *GetUserProfileV2OK {
	return &GetUserProfileV2OK{}
}

/*
GetUserProfileV2OK describes a response with status code 200, with default header values.

User profile data
*/
type GetUserProfileV2OK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.SelfUserWithDataV2
}

// IsSuccess returns true when this get user profile v2 o k response has a 2xx status code
func (o *GetUserProfileV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get user profile v2 o k response has a 3xx status code
func (o *GetUserProfileV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 o k response has a 4xx status code
func (o *GetUserProfileV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get user profile v2 o k response has a 5xx status code
func (o *GetUserProfileV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 o k response a status code equal to that given
func (o *GetUserProfileV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get user profile v2 o k response
func (o *GetUserProfileV2OK) Code() int {
	return 200
}

func (o *GetUserProfileV2OK) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2OK  %+v", 200, o.Payload)
}

func (o *GetUserProfileV2OK) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2OK  %+v", 200, o.Payload)
}

func (o *GetUserProfileV2OK) GetPayload() *models.SelfUserWithDataV2 {
	return o.Payload
}

func (o *GetUserProfileV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.SelfUserWithDataV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileV2Unauthorized creates a GetUserProfileV2Unauthorized with default headers values
func NewGetUserProfileV2Unauthorized() *GetUserProfileV2Unauthorized {
	return &GetUserProfileV2Unauthorized{}
}

/*
GetUserProfileV2Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetUserProfileV2Unauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile v2 unauthorized response has a 2xx status code
func (o *GetUserProfileV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile v2 unauthorized response has a 3xx status code
func (o *GetUserProfileV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 unauthorized response has a 4xx status code
func (o *GetUserProfileV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile v2 unauthorized response has a 5xx status code
func (o *GetUserProfileV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 unauthorized response a status code equal to that given
func (o *GetUserProfileV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get user profile v2 unauthorized response
func (o *GetUserProfileV2Unauthorized) Code() int {
	return 401
}

func (o *GetUserProfileV2Unauthorized) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetUserProfileV2Unauthorized) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetUserProfileV2Unauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileV2Forbidden creates a GetUserProfileV2Forbidden with default headers values
func NewGetUserProfileV2Forbidden() *GetUserProfileV2Forbidden {
	return &GetUserProfileV2Forbidden{}
}

/*
GetUserProfileV2Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetUserProfileV2Forbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile v2 forbidden response has a 2xx status code
func (o *GetUserProfileV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile v2 forbidden response has a 3xx status code
func (o *GetUserProfileV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 forbidden response has a 4xx status code
func (o *GetUserProfileV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile v2 forbidden response has a 5xx status code
func (o *GetUserProfileV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 forbidden response a status code equal to that given
func (o *GetUserProfileV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get user profile v2 forbidden response
func (o *GetUserProfileV2Forbidden) Code() int {
	return 403
}

func (o *GetUserProfileV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetUserProfileV2Forbidden) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetUserProfileV2Forbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileV2NotFound creates a GetUserProfileV2NotFound with default headers values
func NewGetUserProfileV2NotFound() *GetUserProfileV2NotFound {
	return &GetUserProfileV2NotFound{}
}

/*
GetUserProfileV2NotFound describes a response with status code 404, with default header values.

Not found
*/
type GetUserProfileV2NotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile v2 not found response has a 2xx status code
func (o *GetUserProfileV2NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile v2 not found response has a 3xx status code
func (o *GetUserProfileV2NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 not found response has a 4xx status code
func (o *GetUserProfileV2NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile v2 not found response has a 5xx status code
func (o *GetUserProfileV2NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 not found response a status code equal to that given
func (o *GetUserProfileV2NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get user profile v2 not found response
func (o *GetUserProfileV2NotFound) Code() int {
	return 404
}

func (o *GetUserProfileV2NotFound) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2NotFound  %+v", 404, o.Payload)
}

func (o *GetUserProfileV2NotFound) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2NotFound  %+v", 404, o.Payload)
}

func (o *GetUserProfileV2NotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileV2NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileV2PreconditionFailed creates a GetUserProfileV2PreconditionFailed with default headers values
func NewGetUserProfileV2PreconditionFailed() *GetUserProfileV2PreconditionFailed {
	return &GetUserProfileV2PreconditionFailed{}
}

/*
GetUserProfileV2PreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type GetUserProfileV2PreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile v2 precondition failed response has a 2xx status code
func (o *GetUserProfileV2PreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile v2 precondition failed response has a 3xx status code
func (o *GetUserProfileV2PreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 precondition failed response has a 4xx status code
func (o *GetUserProfileV2PreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile v2 precondition failed response has a 5xx status code
func (o *GetUserProfileV2PreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 precondition failed response a status code equal to that given
func (o *GetUserProfileV2PreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get user profile v2 precondition failed response
func (o *GetUserProfileV2PreconditionFailed) Code() int {
	return 412
}

func (o *GetUserProfileV2PreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2PreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetUserProfileV2PreconditionFailed) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2PreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetUserProfileV2PreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileV2PreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileV2TooManyRequests creates a GetUserProfileV2TooManyRequests with default headers values
func NewGetUserProfileV2TooManyRequests() *GetUserProfileV2TooManyRequests {
	return &GetUserProfileV2TooManyRequests{}
}

/*
GetUserProfileV2TooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetUserProfileV2TooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile v2 too many requests response has a 2xx status code
func (o *GetUserProfileV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile v2 too many requests response has a 3xx status code
func (o *GetUserProfileV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile v2 too many requests response has a 4xx status code
func (o *GetUserProfileV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile v2 too many requests response has a 5xx status code
func (o *GetUserProfileV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile v2 too many requests response a status code equal to that given
func (o *GetUserProfileV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get user profile v2 too many requests response
func (o *GetUserProfileV2TooManyRequests) Code() int {
	return 429
}

func (o *GetUserProfileV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetUserProfileV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /v2/self/me][%d] getUserProfileV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetUserProfileV2TooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}