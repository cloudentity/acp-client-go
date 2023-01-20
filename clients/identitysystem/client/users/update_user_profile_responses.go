// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// UpdateUserProfileReader is a Reader for the UpdateUserProfile structure.
type UpdateUserProfileReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateUserProfileReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateUserProfileOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateUserProfileBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateUserProfileUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateUserProfileForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateUserProfileNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdateUserProfileConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewUpdateUserProfilePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateUserProfileUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateUserProfileTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateUserProfileOK creates a UpdateUserProfileOK with default headers values
func NewUpdateUserProfileOK() *UpdateUserProfileOK {
	return &UpdateUserProfileOK{}
}

/*
UpdateUserProfileOK describes a response with status code 200, with default header values.

User profile data
*/
type UpdateUserProfileOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.SelfUserWithData
}

// IsSuccess returns true when this update user profile o k response has a 2xx status code
func (o *UpdateUserProfileOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update user profile o k response has a 3xx status code
func (o *UpdateUserProfileOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile o k response has a 4xx status code
func (o *UpdateUserProfileOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update user profile o k response has a 5xx status code
func (o *UpdateUserProfileOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile o k response a status code equal to that given
func (o *UpdateUserProfileOK) IsCode(code int) bool {
	return code == 200
}

func (o *UpdateUserProfileOK) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileOK  %+v", 200, o.Payload)
}

func (o *UpdateUserProfileOK) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileOK  %+v", 200, o.Payload)
}

func (o *UpdateUserProfileOK) GetPayload() *models.SelfUserWithData {
	return o.Payload
}

func (o *UpdateUserProfileOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewUpdateUserProfileBadRequest creates a UpdateUserProfileBadRequest with default headers values
func NewUpdateUserProfileBadRequest() *UpdateUserProfileBadRequest {
	return &UpdateUserProfileBadRequest{}
}

/*
UpdateUserProfileBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateUserProfileBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile bad request response has a 2xx status code
func (o *UpdateUserProfileBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile bad request response has a 3xx status code
func (o *UpdateUserProfileBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile bad request response has a 4xx status code
func (o *UpdateUserProfileBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile bad request response has a 5xx status code
func (o *UpdateUserProfileBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile bad request response a status code equal to that given
func (o *UpdateUserProfileBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *UpdateUserProfileBadRequest) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateUserProfileBadRequest) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateUserProfileBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileUnauthorized creates a UpdateUserProfileUnauthorized with default headers values
func NewUpdateUserProfileUnauthorized() *UpdateUserProfileUnauthorized {
	return &UpdateUserProfileUnauthorized{}
}

/*
UpdateUserProfileUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateUserProfileUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile unauthorized response has a 2xx status code
func (o *UpdateUserProfileUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile unauthorized response has a 3xx status code
func (o *UpdateUserProfileUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile unauthorized response has a 4xx status code
func (o *UpdateUserProfileUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile unauthorized response has a 5xx status code
func (o *UpdateUserProfileUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile unauthorized response a status code equal to that given
func (o *UpdateUserProfileUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *UpdateUserProfileUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateUserProfileUnauthorized) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateUserProfileUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileForbidden creates a UpdateUserProfileForbidden with default headers values
func NewUpdateUserProfileForbidden() *UpdateUserProfileForbidden {
	return &UpdateUserProfileForbidden{}
}

/*
UpdateUserProfileForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateUserProfileForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile forbidden response has a 2xx status code
func (o *UpdateUserProfileForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile forbidden response has a 3xx status code
func (o *UpdateUserProfileForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile forbidden response has a 4xx status code
func (o *UpdateUserProfileForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile forbidden response has a 5xx status code
func (o *UpdateUserProfileForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile forbidden response a status code equal to that given
func (o *UpdateUserProfileForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *UpdateUserProfileForbidden) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileForbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserProfileForbidden) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileForbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserProfileForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileNotFound creates a UpdateUserProfileNotFound with default headers values
func NewUpdateUserProfileNotFound() *UpdateUserProfileNotFound {
	return &UpdateUserProfileNotFound{}
}

/*
UpdateUserProfileNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateUserProfileNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile not found response has a 2xx status code
func (o *UpdateUserProfileNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile not found response has a 3xx status code
func (o *UpdateUserProfileNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile not found response has a 4xx status code
func (o *UpdateUserProfileNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile not found response has a 5xx status code
func (o *UpdateUserProfileNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile not found response a status code equal to that given
func (o *UpdateUserProfileNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *UpdateUserProfileNotFound) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileNotFound  %+v", 404, o.Payload)
}

func (o *UpdateUserProfileNotFound) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileNotFound  %+v", 404, o.Payload)
}

func (o *UpdateUserProfileNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileConflict creates a UpdateUserProfileConflict with default headers values
func NewUpdateUserProfileConflict() *UpdateUserProfileConflict {
	return &UpdateUserProfileConflict{}
}

/*
UpdateUserProfileConflict describes a response with status code 409, with default header values.

Conflict
*/
type UpdateUserProfileConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile conflict response has a 2xx status code
func (o *UpdateUserProfileConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile conflict response has a 3xx status code
func (o *UpdateUserProfileConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile conflict response has a 4xx status code
func (o *UpdateUserProfileConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile conflict response has a 5xx status code
func (o *UpdateUserProfileConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile conflict response a status code equal to that given
func (o *UpdateUserProfileConflict) IsCode(code int) bool {
	return code == 409
}

func (o *UpdateUserProfileConflict) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileConflict  %+v", 409, o.Payload)
}

func (o *UpdateUserProfileConflict) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileConflict  %+v", 409, o.Payload)
}

func (o *UpdateUserProfileConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfilePreconditionFailed creates a UpdateUserProfilePreconditionFailed with default headers values
func NewUpdateUserProfilePreconditionFailed() *UpdateUserProfilePreconditionFailed {
	return &UpdateUserProfilePreconditionFailed{}
}

/*
UpdateUserProfilePreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type UpdateUserProfilePreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile precondition failed response has a 2xx status code
func (o *UpdateUserProfilePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile precondition failed response has a 3xx status code
func (o *UpdateUserProfilePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile precondition failed response has a 4xx status code
func (o *UpdateUserProfilePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile precondition failed response has a 5xx status code
func (o *UpdateUserProfilePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile precondition failed response a status code equal to that given
func (o *UpdateUserProfilePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *UpdateUserProfilePreconditionFailed) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfilePreconditionFailed  %+v", 412, o.Payload)
}

func (o *UpdateUserProfilePreconditionFailed) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfilePreconditionFailed  %+v", 412, o.Payload)
}

func (o *UpdateUserProfilePreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfilePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileUnprocessableEntity creates a UpdateUserProfileUnprocessableEntity with default headers values
func NewUpdateUserProfileUnprocessableEntity() *UpdateUserProfileUnprocessableEntity {
	return &UpdateUserProfileUnprocessableEntity{}
}

/*
UpdateUserProfileUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateUserProfileUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile unprocessable entity response has a 2xx status code
func (o *UpdateUserProfileUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile unprocessable entity response has a 3xx status code
func (o *UpdateUserProfileUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile unprocessable entity response has a 4xx status code
func (o *UpdateUserProfileUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile unprocessable entity response has a 5xx status code
func (o *UpdateUserProfileUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile unprocessable entity response a status code equal to that given
func (o *UpdateUserProfileUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *UpdateUserProfileUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateUserProfileUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateUserProfileUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserProfileTooManyRequests creates a UpdateUserProfileTooManyRequests with default headers values
func NewUpdateUserProfileTooManyRequests() *UpdateUserProfileTooManyRequests {
	return &UpdateUserProfileTooManyRequests{}
}

/*
UpdateUserProfileTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateUserProfileTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user profile too many requests response has a 2xx status code
func (o *UpdateUserProfileTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user profile too many requests response has a 3xx status code
func (o *UpdateUserProfileTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user profile too many requests response has a 4xx status code
func (o *UpdateUserProfileTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user profile too many requests response has a 5xx status code
func (o *UpdateUserProfileTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update user profile too many requests response a status code equal to that given
func (o *UpdateUserProfileTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *UpdateUserProfileTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateUserProfileTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /self/me][%d] updateUserProfileTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateUserProfileTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserProfileTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
