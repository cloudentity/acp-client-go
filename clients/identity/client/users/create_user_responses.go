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

// CreateUserReader is a Reader for the CreateUser structure.
type CreateUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateUserCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateUserConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateUserCreated creates a CreateUserCreated with default headers values
func NewCreateUserCreated() *CreateUserCreated {
	return &CreateUserCreated{}
}

/* CreateUserCreated describes a response with status code 201, with default header values.

User
*/
type CreateUserCreated struct {
	Payload *models.UserWithData
}

func (o *CreateUserCreated) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserCreated  %+v", 201, o.Payload)
}
func (o *CreateUserCreated) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *CreateUserCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserBadRequest creates a CreateUserBadRequest with default headers values
func NewCreateUserBadRequest() *CreateUserBadRequest {
	return &CreateUserBadRequest{}
}

/* CreateUserBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateUserBadRequest struct {
	Payload *models.Error
}

func (o *CreateUserBadRequest) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserBadRequest  %+v", 400, o.Payload)
}
func (o *CreateUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserUnauthorized creates a CreateUserUnauthorized with default headers values
func NewCreateUserUnauthorized() *CreateUserUnauthorized {
	return &CreateUserUnauthorized{}
}

/* CreateUserUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateUserUnauthorized struct {
	Payload *models.Error
}

func (o *CreateUserUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserForbidden creates a CreateUserForbidden with default headers values
func NewCreateUserForbidden() *CreateUserForbidden {
	return &CreateUserForbidden{}
}

/* CreateUserForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateUserForbidden struct {
	Payload *models.Error
}

func (o *CreateUserForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserForbidden  %+v", 403, o.Payload)
}
func (o *CreateUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserNotFound creates a CreateUserNotFound with default headers values
func NewCreateUserNotFound() *CreateUserNotFound {
	return &CreateUserNotFound{}
}

/* CreateUserNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateUserNotFound struct {
	Payload *models.Error
}

func (o *CreateUserNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserNotFound  %+v", 404, o.Payload)
}
func (o *CreateUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserConflict creates a CreateUserConflict with default headers values
func NewCreateUserConflict() *CreateUserConflict {
	return &CreateUserConflict{}
}

/* CreateUserConflict describes a response with status code 409, with default header values.

HttpError
*/
type CreateUserConflict struct {
	Payload *models.Error
}

func (o *CreateUserConflict) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserConflict  %+v", 409, o.Payload)
}
func (o *CreateUserConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserUnprocessableEntity creates a CreateUserUnprocessableEntity with default headers values
func NewCreateUserUnprocessableEntity() *CreateUserUnprocessableEntity {
	return &CreateUserUnprocessableEntity{}
}

/* CreateUserUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateUserUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateUserUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateUserTooManyRequests creates a CreateUserTooManyRequests with default headers values
func NewCreateUserTooManyRequests() *CreateUserTooManyRequests {
	return &CreateUserTooManyRequests{}
}

/* CreateUserTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateUserTooManyRequests struct {
	Payload *models.Error
}

func (o *CreateUserTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users][%d] createUserTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}