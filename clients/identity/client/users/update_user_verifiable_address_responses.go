// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// UpdateUserVerifiableAddressReader is a Reader for the UpdateUserVerifiableAddress structure.
type UpdateUserVerifiableAddressReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateUserVerifiableAddressReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateUserVerifiableAddressOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUpdateUserVerifiableAddressUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateUserVerifiableAddressForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateUserVerifiableAddressNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdateUserVerifiableAddressConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateUserVerifiableAddressUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users/{userID}/addresses/update] updateUserVerifiableAddress", response, response.Code())
	}
}

// NewUpdateUserVerifiableAddressOK creates a UpdateUserVerifiableAddressOK with default headers values
func NewUpdateUserVerifiableAddressOK() *UpdateUserVerifiableAddressOK {
	return &UpdateUserVerifiableAddressOK{}
}

/*
UpdateUserVerifiableAddressOK describes a response with status code 200, with default header values.

Address
*/
type UpdateUserVerifiableAddressOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.UserVerifiableAddress
}

// IsSuccess returns true when this update user verifiable address o k response has a 2xx status code
func (o *UpdateUserVerifiableAddressOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update user verifiable address o k response has a 3xx status code
func (o *UpdateUserVerifiableAddressOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address o k response has a 4xx status code
func (o *UpdateUserVerifiableAddressOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update user verifiable address o k response has a 5xx status code
func (o *UpdateUserVerifiableAddressOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address o k response a status code equal to that given
func (o *UpdateUserVerifiableAddressOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update user verifiable address o k response
func (o *UpdateUserVerifiableAddressOK) Code() int {
	return 200
}

func (o *UpdateUserVerifiableAddressOK) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressOK  %+v", 200, o.Payload)
}

func (o *UpdateUserVerifiableAddressOK) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressOK  %+v", 200, o.Payload)
}

func (o *UpdateUserVerifiableAddressOK) GetPayload() *models.UserVerifiableAddress {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.UserVerifiableAddress)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserVerifiableAddressUnauthorized creates a UpdateUserVerifiableAddressUnauthorized with default headers values
func NewUpdateUserVerifiableAddressUnauthorized() *UpdateUserVerifiableAddressUnauthorized {
	return &UpdateUserVerifiableAddressUnauthorized{}
}

/*
UpdateUserVerifiableAddressUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateUserVerifiableAddressUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user verifiable address unauthorized response has a 2xx status code
func (o *UpdateUserVerifiableAddressUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user verifiable address unauthorized response has a 3xx status code
func (o *UpdateUserVerifiableAddressUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address unauthorized response has a 4xx status code
func (o *UpdateUserVerifiableAddressUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user verifiable address unauthorized response has a 5xx status code
func (o *UpdateUserVerifiableAddressUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address unauthorized response a status code equal to that given
func (o *UpdateUserVerifiableAddressUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update user verifiable address unauthorized response
func (o *UpdateUserVerifiableAddressUnauthorized) Code() int {
	return 401
}

func (o *UpdateUserVerifiableAddressUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateUserVerifiableAddressUnauthorized) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateUserVerifiableAddressUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserVerifiableAddressForbidden creates a UpdateUserVerifiableAddressForbidden with default headers values
func NewUpdateUserVerifiableAddressForbidden() *UpdateUserVerifiableAddressForbidden {
	return &UpdateUserVerifiableAddressForbidden{}
}

/*
UpdateUserVerifiableAddressForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateUserVerifiableAddressForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user verifiable address forbidden response has a 2xx status code
func (o *UpdateUserVerifiableAddressForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user verifiable address forbidden response has a 3xx status code
func (o *UpdateUserVerifiableAddressForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address forbidden response has a 4xx status code
func (o *UpdateUserVerifiableAddressForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user verifiable address forbidden response has a 5xx status code
func (o *UpdateUserVerifiableAddressForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address forbidden response a status code equal to that given
func (o *UpdateUserVerifiableAddressForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update user verifiable address forbidden response
func (o *UpdateUserVerifiableAddressForbidden) Code() int {
	return 403
}

func (o *UpdateUserVerifiableAddressForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserVerifiableAddressForbidden) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressForbidden  %+v", 403, o.Payload)
}

func (o *UpdateUserVerifiableAddressForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserVerifiableAddressNotFound creates a UpdateUserVerifiableAddressNotFound with default headers values
func NewUpdateUserVerifiableAddressNotFound() *UpdateUserVerifiableAddressNotFound {
	return &UpdateUserVerifiableAddressNotFound{}
}

/*
UpdateUserVerifiableAddressNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateUserVerifiableAddressNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user verifiable address not found response has a 2xx status code
func (o *UpdateUserVerifiableAddressNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user verifiable address not found response has a 3xx status code
func (o *UpdateUserVerifiableAddressNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address not found response has a 4xx status code
func (o *UpdateUserVerifiableAddressNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user verifiable address not found response has a 5xx status code
func (o *UpdateUserVerifiableAddressNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address not found response a status code equal to that given
func (o *UpdateUserVerifiableAddressNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update user verifiable address not found response
func (o *UpdateUserVerifiableAddressNotFound) Code() int {
	return 404
}

func (o *UpdateUserVerifiableAddressNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *UpdateUserVerifiableAddressNotFound) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressNotFound  %+v", 404, o.Payload)
}

func (o *UpdateUserVerifiableAddressNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserVerifiableAddressConflict creates a UpdateUserVerifiableAddressConflict with default headers values
func NewUpdateUserVerifiableAddressConflict() *UpdateUserVerifiableAddressConflict {
	return &UpdateUserVerifiableAddressConflict{}
}

/*
UpdateUserVerifiableAddressConflict describes a response with status code 409, with default header values.

Conflict
*/
type UpdateUserVerifiableAddressConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user verifiable address conflict response has a 2xx status code
func (o *UpdateUserVerifiableAddressConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user verifiable address conflict response has a 3xx status code
func (o *UpdateUserVerifiableAddressConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address conflict response has a 4xx status code
func (o *UpdateUserVerifiableAddressConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user verifiable address conflict response has a 5xx status code
func (o *UpdateUserVerifiableAddressConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address conflict response a status code equal to that given
func (o *UpdateUserVerifiableAddressConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the update user verifiable address conflict response
func (o *UpdateUserVerifiableAddressConflict) Code() int {
	return 409
}

func (o *UpdateUserVerifiableAddressConflict) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressConflict  %+v", 409, o.Payload)
}

func (o *UpdateUserVerifiableAddressConflict) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressConflict  %+v", 409, o.Payload)
}

func (o *UpdateUserVerifiableAddressConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateUserVerifiableAddressUnprocessableEntity creates a UpdateUserVerifiableAddressUnprocessableEntity with default headers values
func NewUpdateUserVerifiableAddressUnprocessableEntity() *UpdateUserVerifiableAddressUnprocessableEntity {
	return &UpdateUserVerifiableAddressUnprocessableEntity{}
}

/*
UpdateUserVerifiableAddressUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateUserVerifiableAddressUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update user verifiable address unprocessable entity response has a 2xx status code
func (o *UpdateUserVerifiableAddressUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update user verifiable address unprocessable entity response has a 3xx status code
func (o *UpdateUserVerifiableAddressUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user verifiable address unprocessable entity response has a 4xx status code
func (o *UpdateUserVerifiableAddressUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update user verifiable address unprocessable entity response has a 5xx status code
func (o *UpdateUserVerifiableAddressUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update user verifiable address unprocessable entity response a status code equal to that given
func (o *UpdateUserVerifiableAddressUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update user verifiable address unprocessable entity response
func (o *UpdateUserVerifiableAddressUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateUserVerifiableAddressUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateUserVerifiableAddressUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/addresses/update][%d] updateUserVerifiableAddressUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateUserVerifiableAddressUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateUserVerifiableAddressUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
