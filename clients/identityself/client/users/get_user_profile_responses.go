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

	"github.com/cloudentity/acp-client-go/clients/identityself/models"
)

// GetUserProfileReader is a Reader for the GetUserProfile structure.
type GetUserProfileReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUserProfileReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUserProfileOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetUserProfileUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetUserProfileForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetUserProfileNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetUserProfilePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetUserProfileTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /self/me] getUserProfile", response, response.Code())
	}
}

// NewGetUserProfileOK creates a GetUserProfileOK with default headers values
func NewGetUserProfileOK() *GetUserProfileOK {
	return &GetUserProfileOK{}
}

/*
GetUserProfileOK describes a response with status code 200, with default header values.

User profile data
*/
type GetUserProfileOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.SelfUserWithData
}

// IsSuccess returns true when this get user profile o k response has a 2xx status code
func (o *GetUserProfileOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get user profile o k response has a 3xx status code
func (o *GetUserProfileOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile o k response has a 4xx status code
func (o *GetUserProfileOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get user profile o k response has a 5xx status code
func (o *GetUserProfileOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile o k response a status code equal to that given
func (o *GetUserProfileOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get user profile o k response
func (o *GetUserProfileOK) Code() int {
	return 200
}

func (o *GetUserProfileOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileOK %s", 200, payload)
}

func (o *GetUserProfileOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileOK %s", 200, payload)
}

func (o *GetUserProfileOK) GetPayload() *models.SelfUserWithData {
	return o.Payload
}

func (o *GetUserProfileOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.SelfUserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileUnauthorized creates a GetUserProfileUnauthorized with default headers values
func NewGetUserProfileUnauthorized() *GetUserProfileUnauthorized {
	return &GetUserProfileUnauthorized{}
}

/*
GetUserProfileUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetUserProfileUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile unauthorized response has a 2xx status code
func (o *GetUserProfileUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile unauthorized response has a 3xx status code
func (o *GetUserProfileUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile unauthorized response has a 4xx status code
func (o *GetUserProfileUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile unauthorized response has a 5xx status code
func (o *GetUserProfileUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile unauthorized response a status code equal to that given
func (o *GetUserProfileUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get user profile unauthorized response
func (o *GetUserProfileUnauthorized) Code() int {
	return 401
}

func (o *GetUserProfileUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileUnauthorized %s", 401, payload)
}

func (o *GetUserProfileUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileUnauthorized %s", 401, payload)
}

func (o *GetUserProfileUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileForbidden creates a GetUserProfileForbidden with default headers values
func NewGetUserProfileForbidden() *GetUserProfileForbidden {
	return &GetUserProfileForbidden{}
}

/*
GetUserProfileForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetUserProfileForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile forbidden response has a 2xx status code
func (o *GetUserProfileForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile forbidden response has a 3xx status code
func (o *GetUserProfileForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile forbidden response has a 4xx status code
func (o *GetUserProfileForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile forbidden response has a 5xx status code
func (o *GetUserProfileForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile forbidden response a status code equal to that given
func (o *GetUserProfileForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get user profile forbidden response
func (o *GetUserProfileForbidden) Code() int {
	return 403
}

func (o *GetUserProfileForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileForbidden %s", 403, payload)
}

func (o *GetUserProfileForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileForbidden %s", 403, payload)
}

func (o *GetUserProfileForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileNotFound creates a GetUserProfileNotFound with default headers values
func NewGetUserProfileNotFound() *GetUserProfileNotFound {
	return &GetUserProfileNotFound{}
}

/*
GetUserProfileNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetUserProfileNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile not found response has a 2xx status code
func (o *GetUserProfileNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile not found response has a 3xx status code
func (o *GetUserProfileNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile not found response has a 4xx status code
func (o *GetUserProfileNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile not found response has a 5xx status code
func (o *GetUserProfileNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile not found response a status code equal to that given
func (o *GetUserProfileNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get user profile not found response
func (o *GetUserProfileNotFound) Code() int {
	return 404
}

func (o *GetUserProfileNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileNotFound %s", 404, payload)
}

func (o *GetUserProfileNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileNotFound %s", 404, payload)
}

func (o *GetUserProfileNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfilePreconditionFailed creates a GetUserProfilePreconditionFailed with default headers values
func NewGetUserProfilePreconditionFailed() *GetUserProfilePreconditionFailed {
	return &GetUserProfilePreconditionFailed{}
}

/*
GetUserProfilePreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type GetUserProfilePreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile precondition failed response has a 2xx status code
func (o *GetUserProfilePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile precondition failed response has a 3xx status code
func (o *GetUserProfilePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile precondition failed response has a 4xx status code
func (o *GetUserProfilePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile precondition failed response has a 5xx status code
func (o *GetUserProfilePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile precondition failed response a status code equal to that given
func (o *GetUserProfilePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get user profile precondition failed response
func (o *GetUserProfilePreconditionFailed) Code() int {
	return 412
}

func (o *GetUserProfilePreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfilePreconditionFailed %s", 412, payload)
}

func (o *GetUserProfilePreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfilePreconditionFailed %s", 412, payload)
}

func (o *GetUserProfilePreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfilePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserProfileTooManyRequests creates a GetUserProfileTooManyRequests with default headers values
func NewGetUserProfileTooManyRequests() *GetUserProfileTooManyRequests {
	return &GetUserProfileTooManyRequests{}
}

/*
GetUserProfileTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetUserProfileTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get user profile too many requests response has a 2xx status code
func (o *GetUserProfileTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get user profile too many requests response has a 3xx status code
func (o *GetUserProfileTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get user profile too many requests response has a 4xx status code
func (o *GetUserProfileTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get user profile too many requests response has a 5xx status code
func (o *GetUserProfileTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get user profile too many requests response a status code equal to that given
func (o *GetUserProfileTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get user profile too many requests response
func (o *GetUserProfileTooManyRequests) Code() int {
	return 429
}

func (o *GetUserProfileTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileTooManyRequests %s", 429, payload)
}

func (o *GetUserProfileTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /self/me][%d] getUserProfileTooManyRequests %s", 429, payload)
}

func (o *GetUserProfileTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetUserProfileTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
