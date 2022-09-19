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

// ActivateSelfRegisteredUserUsingExtendedCodeReader is a Reader for the ActivateSelfRegisteredUserUsingExtendedCode structure.
type ActivateSelfRegisteredUserUsingExtendedCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ActivateSelfRegisteredUserUsingExtendedCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewActivateSelfRegisteredUserUsingExtendedCodeCreated creates a ActivateSelfRegisteredUserUsingExtendedCodeCreated with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeCreated() *ActivateSelfRegisteredUserUsingExtendedCodeCreated {
	return &ActivateSelfRegisteredUserUsingExtendedCodeCreated{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeCreated describes a response with status code 201, with default header values.

User
*/
type ActivateSelfRegisteredUserUsingExtendedCodeCreated struct {
	Payload *models.UserWithData
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeCreated  %+v", 201, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeCreated) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivateSelfRegisteredUserUsingExtendedCodeBadRequest creates a ActivateSelfRegisteredUserUsingExtendedCodeBadRequest with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeBadRequest() *ActivateSelfRegisteredUserUsingExtendedCodeBadRequest {
	return &ActivateSelfRegisteredUserUsingExtendedCodeBadRequest{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ActivateSelfRegisteredUserUsingExtendedCodeBadRequest struct {
	Payload *models.Error
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeBadRequest  %+v", 400, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivateSelfRegisteredUserUsingExtendedCodeUnauthorized creates a ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeUnauthorized() *ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized {
	return &ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized struct {
	Payload *models.Error
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeUnauthorized  %+v", 401, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivateSelfRegisteredUserUsingExtendedCodeNotFound creates a ActivateSelfRegisteredUserUsingExtendedCodeNotFound with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeNotFound() *ActivateSelfRegisteredUserUsingExtendedCodeNotFound {
	return &ActivateSelfRegisteredUserUsingExtendedCodeNotFound{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ActivateSelfRegisteredUserUsingExtendedCodeNotFound struct {
	Payload *models.Error
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeNotFound  %+v", 404, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity creates a ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity() *ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity {
	return &ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity struct {
	Payload *models.Error
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests creates a ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests with default headers values
func NewActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests() *ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests {
	return &ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests{}
}

/* ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests struct {
	Payload *models.Error
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/user/activate][%d] activateSelfRegisteredUserUsingExtendedCodeTooManyRequests  %+v", 429, o.Payload)
}
func (o *ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ActivateSelfRegisteredUserUsingExtendedCodeTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}