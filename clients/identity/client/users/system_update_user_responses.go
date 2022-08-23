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

// SystemUpdateUserReader is a Reader for the SystemUpdateUser structure.
type SystemUpdateUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemUpdateUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemUpdateUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemUpdateUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemUpdateUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemUpdateUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemUpdateUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSystemUpdateUserConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemUpdateUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemUpdateUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemUpdateUserOK creates a SystemUpdateUserOK with default headers values
func NewSystemUpdateUserOK() *SystemUpdateUserOK {
	return &SystemUpdateUserOK{}
}

/* SystemUpdateUserOK describes a response with status code 200, with default header values.

User
*/
type SystemUpdateUserOK struct {
	Payload *models.UserWithData
}

func (o *SystemUpdateUserOK) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserOK  %+v", 200, o.Payload)
}
func (o *SystemUpdateUserOK) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *SystemUpdateUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserBadRequest creates a SystemUpdateUserBadRequest with default headers values
func NewSystemUpdateUserBadRequest() *SystemUpdateUserBadRequest {
	return &SystemUpdateUserBadRequest{}
}

/* SystemUpdateUserBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type SystemUpdateUserBadRequest struct {
	Payload *models.Error
}

func (o *SystemUpdateUserBadRequest) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserBadRequest  %+v", 400, o.Payload)
}
func (o *SystemUpdateUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserUnauthorized creates a SystemUpdateUserUnauthorized with default headers values
func NewSystemUpdateUserUnauthorized() *SystemUpdateUserUnauthorized {
	return &SystemUpdateUserUnauthorized{}
}

/* SystemUpdateUserUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SystemUpdateUserUnauthorized struct {
	Payload *models.Error
}

func (o *SystemUpdateUserUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserUnauthorized  %+v", 401, o.Payload)
}
func (o *SystemUpdateUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserForbidden creates a SystemUpdateUserForbidden with default headers values
func NewSystemUpdateUserForbidden() *SystemUpdateUserForbidden {
	return &SystemUpdateUserForbidden{}
}

/* SystemUpdateUserForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SystemUpdateUserForbidden struct {
	Payload *models.Error
}

func (o *SystemUpdateUserForbidden) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserForbidden  %+v", 403, o.Payload)
}
func (o *SystemUpdateUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserNotFound creates a SystemUpdateUserNotFound with default headers values
func NewSystemUpdateUserNotFound() *SystemUpdateUserNotFound {
	return &SystemUpdateUserNotFound{}
}

/* SystemUpdateUserNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SystemUpdateUserNotFound struct {
	Payload *models.Error
}

func (o *SystemUpdateUserNotFound) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserNotFound  %+v", 404, o.Payload)
}
func (o *SystemUpdateUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserConflict creates a SystemUpdateUserConflict with default headers values
func NewSystemUpdateUserConflict() *SystemUpdateUserConflict {
	return &SystemUpdateUserConflict{}
}

/* SystemUpdateUserConflict describes a response with status code 409, with default header values.

HttpError
*/
type SystemUpdateUserConflict struct {
	Payload *models.Error
}

func (o *SystemUpdateUserConflict) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserConflict  %+v", 409, o.Payload)
}
func (o *SystemUpdateUserConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserUnprocessableEntity creates a SystemUpdateUserUnprocessableEntity with default headers values
func NewSystemUpdateUserUnprocessableEntity() *SystemUpdateUserUnprocessableEntity {
	return &SystemUpdateUserUnprocessableEntity{}
}

/* SystemUpdateUserUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type SystemUpdateUserUnprocessableEntity struct {
	Payload *models.Error
}

func (o *SystemUpdateUserUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *SystemUpdateUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateUserTooManyRequests creates a SystemUpdateUserTooManyRequests with default headers values
func NewSystemUpdateUserTooManyRequests() *SystemUpdateUserTooManyRequests {
	return &SystemUpdateUserTooManyRequests{}
}

/* SystemUpdateUserTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SystemUpdateUserTooManyRequests struct {
	Payload *models.Error
}

func (o *SystemUpdateUserTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /system/pools/{ipID}/users/{userID}][%d] systemUpdateUserTooManyRequests  %+v", 429, o.Payload)
}
func (o *SystemUpdateUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
