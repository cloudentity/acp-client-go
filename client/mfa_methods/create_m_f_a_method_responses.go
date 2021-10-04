// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// CreateMFAMethodReader is a Reader for the CreateMFAMethod structure.
type CreateMFAMethodReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateMFAMethodReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateMFAMethodCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateMFAMethodBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateMFAMethodUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateMFAMethodForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateMFAMethodNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateMFAMethodConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateMFAMethodUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateMFAMethodCreated creates a CreateMFAMethodCreated with default headers values
func NewCreateMFAMethodCreated() *CreateMFAMethodCreated {
	return &CreateMFAMethodCreated{}
}

/* CreateMFAMethodCreated describes a response with status code 201, with default header values.

MFAMethod
*/
type CreateMFAMethodCreated struct {
	Payload *models.MFAMethod
}

func (o *CreateMFAMethodCreated) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodCreated  %+v", 201, o.Payload)
}
func (o *CreateMFAMethodCreated) GetPayload() *models.MFAMethod {
	return o.Payload
}

func (o *CreateMFAMethodCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MFAMethod)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodBadRequest creates a CreateMFAMethodBadRequest with default headers values
func NewCreateMFAMethodBadRequest() *CreateMFAMethodBadRequest {
	return &CreateMFAMethodBadRequest{}
}

/* CreateMFAMethodBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateMFAMethodBadRequest struct {
	Payload *models.Error
}

func (o *CreateMFAMethodBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodBadRequest  %+v", 400, o.Payload)
}
func (o *CreateMFAMethodBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodUnauthorized creates a CreateMFAMethodUnauthorized with default headers values
func NewCreateMFAMethodUnauthorized() *CreateMFAMethodUnauthorized {
	return &CreateMFAMethodUnauthorized{}
}

/* CreateMFAMethodUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateMFAMethodUnauthorized struct {
	Payload *models.Error
}

func (o *CreateMFAMethodUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateMFAMethodUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodForbidden creates a CreateMFAMethodForbidden with default headers values
func NewCreateMFAMethodForbidden() *CreateMFAMethodForbidden {
	return &CreateMFAMethodForbidden{}
}

/* CreateMFAMethodForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateMFAMethodForbidden struct {
	Payload *models.Error
}

func (o *CreateMFAMethodForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodForbidden  %+v", 403, o.Payload)
}
func (o *CreateMFAMethodForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodNotFound creates a CreateMFAMethodNotFound with default headers values
func NewCreateMFAMethodNotFound() *CreateMFAMethodNotFound {
	return &CreateMFAMethodNotFound{}
}

/* CreateMFAMethodNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateMFAMethodNotFound struct {
	Payload *models.Error
}

func (o *CreateMFAMethodNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodNotFound  %+v", 404, o.Payload)
}
func (o *CreateMFAMethodNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodConflict creates a CreateMFAMethodConflict with default headers values
func NewCreateMFAMethodConflict() *CreateMFAMethodConflict {
	return &CreateMFAMethodConflict{}
}

/* CreateMFAMethodConflict describes a response with status code 409, with default header values.

HttpError
*/
type CreateMFAMethodConflict struct {
	Payload *models.Error
}

func (o *CreateMFAMethodConflict) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodConflict  %+v", 409, o.Payload)
}
func (o *CreateMFAMethodConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMFAMethodUnprocessableEntity creates a CreateMFAMethodUnprocessableEntity with default headers values
func NewCreateMFAMethodUnprocessableEntity() *CreateMFAMethodUnprocessableEntity {
	return &CreateMFAMethodUnprocessableEntity{}
}

/* CreateMFAMethodUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateMFAMethodUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateMFAMethodUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/mfa-methods][%d] createMFAMethodUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateMFAMethodUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateMFAMethodUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
