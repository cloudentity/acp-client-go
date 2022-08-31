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

// SelfRegisterUserReader is a Reader for the SelfRegisterUser structure.
type SelfRegisterUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SelfRegisterUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewSelfRegisterUserCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSelfRegisterUserBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSelfRegisterUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSelfRegisterUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSelfRegisterUserUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSelfRegisterUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSelfRegisterUserCreated creates a SelfRegisterUserCreated with default headers values
func NewSelfRegisterUserCreated() *SelfRegisterUserCreated {
	return &SelfRegisterUserCreated{}
}

/* SelfRegisterUserCreated describes a response with status code 201, with default header values.

User
*/
type SelfRegisterUserCreated struct {
	Payload *models.UserID
}

func (o *SelfRegisterUserCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserCreated  %+v", 201, o.Payload)
}
func (o *SelfRegisterUserCreated) GetPayload() *models.UserID {
	return o.Payload
}

func (o *SelfRegisterUserCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserID)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSelfRegisterUserBadRequest creates a SelfRegisterUserBadRequest with default headers values
func NewSelfRegisterUserBadRequest() *SelfRegisterUserBadRequest {
	return &SelfRegisterUserBadRequest{}
}

/* SelfRegisterUserBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type SelfRegisterUserBadRequest struct {
	Payload *models.Error
}

func (o *SelfRegisterUserBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserBadRequest  %+v", 400, o.Payload)
}
func (o *SelfRegisterUserBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SelfRegisterUserBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSelfRegisterUserUnauthorized creates a SelfRegisterUserUnauthorized with default headers values
func NewSelfRegisterUserUnauthorized() *SelfRegisterUserUnauthorized {
	return &SelfRegisterUserUnauthorized{}
}

/* SelfRegisterUserUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SelfRegisterUserUnauthorized struct {
	Payload *models.Error
}

func (o *SelfRegisterUserUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserUnauthorized  %+v", 401, o.Payload)
}
func (o *SelfRegisterUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SelfRegisterUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSelfRegisterUserNotFound creates a SelfRegisterUserNotFound with default headers values
func NewSelfRegisterUserNotFound() *SelfRegisterUserNotFound {
	return &SelfRegisterUserNotFound{}
}

/* SelfRegisterUserNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SelfRegisterUserNotFound struct {
	Payload *models.Error
}

func (o *SelfRegisterUserNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserNotFound  %+v", 404, o.Payload)
}
func (o *SelfRegisterUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SelfRegisterUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSelfRegisterUserUnprocessableEntity creates a SelfRegisterUserUnprocessableEntity with default headers values
func NewSelfRegisterUserUnprocessableEntity() *SelfRegisterUserUnprocessableEntity {
	return &SelfRegisterUserUnprocessableEntity{}
}

/* SelfRegisterUserUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type SelfRegisterUserUnprocessableEntity struct {
	Payload *models.Error
}

func (o *SelfRegisterUserUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *SelfRegisterUserUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SelfRegisterUserUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSelfRegisterUserTooManyRequests creates a SelfRegisterUserTooManyRequests with default headers values
func NewSelfRegisterUserTooManyRequests() *SelfRegisterUserTooManyRequests {
	return &SelfRegisterUserTooManyRequests{}
}

/* SelfRegisterUserTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SelfRegisterUserTooManyRequests struct {
	Payload *models.Error
}

func (o *SelfRegisterUserTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/register][%d] selfRegisterUserTooManyRequests  %+v", 429, o.Payload)
}
func (o *SelfRegisterUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SelfRegisterUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}