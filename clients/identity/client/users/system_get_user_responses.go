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

// SystemGetUserReader is a Reader for the SystemGetUser structure.
type SystemGetUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemGetUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemGetUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemGetUserUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemGetUserForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemGetUserNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemGetUserTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemGetUserOK creates a SystemGetUserOK with default headers values
func NewSystemGetUserOK() *SystemGetUserOK {
	return &SystemGetUserOK{}
}

/* SystemGetUserOK describes a response with status code 200, with default header values.

User
*/
type SystemGetUserOK struct {
	Payload *models.UserWithData
}

func (o *SystemGetUserOK) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserOK  %+v", 200, o.Payload)
}
func (o *SystemGetUserOK) GetPayload() *models.UserWithData {
	return o.Payload
}

func (o *SystemGetUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UserWithData)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserUnauthorized creates a SystemGetUserUnauthorized with default headers values
func NewSystemGetUserUnauthorized() *SystemGetUserUnauthorized {
	return &SystemGetUserUnauthorized{}
}

/* SystemGetUserUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SystemGetUserUnauthorized struct {
	Payload *models.Error
}

func (o *SystemGetUserUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserUnauthorized  %+v", 401, o.Payload)
}
func (o *SystemGetUserUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserForbidden creates a SystemGetUserForbidden with default headers values
func NewSystemGetUserForbidden() *SystemGetUserForbidden {
	return &SystemGetUserForbidden{}
}

/* SystemGetUserForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SystemGetUserForbidden struct {
	Payload *models.Error
}

func (o *SystemGetUserForbidden) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserForbidden  %+v", 403, o.Payload)
}
func (o *SystemGetUserForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserNotFound creates a SystemGetUserNotFound with default headers values
func NewSystemGetUserNotFound() *SystemGetUserNotFound {
	return &SystemGetUserNotFound{}
}

/* SystemGetUserNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SystemGetUserNotFound struct {
	Payload *models.Error
}

func (o *SystemGetUserNotFound) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserNotFound  %+v", 404, o.Payload)
}
func (o *SystemGetUserNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetUserTooManyRequests creates a SystemGetUserTooManyRequests with default headers values
func NewSystemGetUserTooManyRequests() *SystemGetUserTooManyRequests {
	return &SystemGetUserTooManyRequests{}
}

/* SystemGetUserTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SystemGetUserTooManyRequests struct {
	Payload *models.Error
}

func (o *SystemGetUserTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}/users/{userID}][%d] systemGetUserTooManyRequests  %+v", 429, o.Payload)
}
func (o *SystemGetUserTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetUserTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}