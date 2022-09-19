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

// GenerateActivationCodeReader is a Reader for the GenerateActivationCode structure.
type GenerateActivationCodeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GenerateActivationCodeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewGenerateActivationCodeCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGenerateActivationCodeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGenerateActivationCodeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGenerateActivationCodeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGenerateActivationCodeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGenerateActivationCodeTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGenerateActivationCodeCreated creates a GenerateActivationCodeCreated with default headers values
func NewGenerateActivationCodeCreated() *GenerateActivationCodeCreated {
	return &GenerateActivationCodeCreated{}
}

/* GenerateActivationCodeCreated describes a response with status code 201, with default header values.

User
*/
type GenerateActivationCodeCreated struct {
	Payload *models.CodeID
}

func (o *GenerateActivationCodeCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeCreated  %+v", 201, o.Payload)
}
func (o *GenerateActivationCodeCreated) GetPayload() *models.CodeID {
	return o.Payload
}

func (o *GenerateActivationCodeCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CodeID)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateActivationCodeBadRequest creates a GenerateActivationCodeBadRequest with default headers values
func NewGenerateActivationCodeBadRequest() *GenerateActivationCodeBadRequest {
	return &GenerateActivationCodeBadRequest{}
}

/* GenerateActivationCodeBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type GenerateActivationCodeBadRequest struct {
	Payload *models.Error
}

func (o *GenerateActivationCodeBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeBadRequest  %+v", 400, o.Payload)
}
func (o *GenerateActivationCodeBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateActivationCodeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateActivationCodeUnauthorized creates a GenerateActivationCodeUnauthorized with default headers values
func NewGenerateActivationCodeUnauthorized() *GenerateActivationCodeUnauthorized {
	return &GenerateActivationCodeUnauthorized{}
}

/* GenerateActivationCodeUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GenerateActivationCodeUnauthorized struct {
	Payload *models.Error
}

func (o *GenerateActivationCodeUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeUnauthorized  %+v", 401, o.Payload)
}
func (o *GenerateActivationCodeUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateActivationCodeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateActivationCodeNotFound creates a GenerateActivationCodeNotFound with default headers values
func NewGenerateActivationCodeNotFound() *GenerateActivationCodeNotFound {
	return &GenerateActivationCodeNotFound{}
}

/* GenerateActivationCodeNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GenerateActivationCodeNotFound struct {
	Payload *models.Error
}

func (o *GenerateActivationCodeNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeNotFound  %+v", 404, o.Payload)
}
func (o *GenerateActivationCodeNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateActivationCodeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateActivationCodeUnprocessableEntity creates a GenerateActivationCodeUnprocessableEntity with default headers values
func NewGenerateActivationCodeUnprocessableEntity() *GenerateActivationCodeUnprocessableEntity {
	return &GenerateActivationCodeUnprocessableEntity{}
}

/* GenerateActivationCodeUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type GenerateActivationCodeUnprocessableEntity struct {
	Payload *models.Error
}

func (o *GenerateActivationCodeUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *GenerateActivationCodeUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateActivationCodeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGenerateActivationCodeTooManyRequests creates a GenerateActivationCodeTooManyRequests with default headers values
func NewGenerateActivationCodeTooManyRequests() *GenerateActivationCodeTooManyRequests {
	return &GenerateActivationCodeTooManyRequests{}
}

/* GenerateActivationCodeTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GenerateActivationCodeTooManyRequests struct {
	Payload *models.Error
}

func (o *GenerateActivationCodeTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/activation/generate][%d] generateActivationCodeTooManyRequests  %+v", 429, o.Payload)
}
func (o *GenerateActivationCodeTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GenerateActivationCodeTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}