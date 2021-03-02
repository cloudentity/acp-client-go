// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// CreateAuthorizationServerReader is a Reader for the CreateAuthorizationServer structure.
type CreateAuthorizationServerReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAuthorizationServerReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAuthorizationServerCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAuthorizationServerBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAuthorizationServerUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAuthorizationServerForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAuthorizationServerNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateAuthorizationServerConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAuthorizationServerUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAuthorizationServerCreated creates a CreateAuthorizationServerCreated with default headers values
func NewCreateAuthorizationServerCreated() *CreateAuthorizationServerCreated {
	return &CreateAuthorizationServerCreated{}
}

/* CreateAuthorizationServerCreated describes a response with status code 201, with default header values.

Server
*/
type CreateAuthorizationServerCreated struct {
	Payload *models.Server
}

func (o *CreateAuthorizationServerCreated) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerCreated  %+v", 201, o.Payload)
}
func (o *CreateAuthorizationServerCreated) GetPayload() *models.Server {
	return o.Payload
}

func (o *CreateAuthorizationServerCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Server)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerBadRequest creates a CreateAuthorizationServerBadRequest with default headers values
func NewCreateAuthorizationServerBadRequest() *CreateAuthorizationServerBadRequest {
	return &CreateAuthorizationServerBadRequest{}
}

/* CreateAuthorizationServerBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateAuthorizationServerBadRequest struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerBadRequest  %+v", 400, o.Payload)
}
func (o *CreateAuthorizationServerBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerUnauthorized creates a CreateAuthorizationServerUnauthorized with default headers values
func NewCreateAuthorizationServerUnauthorized() *CreateAuthorizationServerUnauthorized {
	return &CreateAuthorizationServerUnauthorized{}
}

/* CreateAuthorizationServerUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateAuthorizationServerUnauthorized struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateAuthorizationServerUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerForbidden creates a CreateAuthorizationServerForbidden with default headers values
func NewCreateAuthorizationServerForbidden() *CreateAuthorizationServerForbidden {
	return &CreateAuthorizationServerForbidden{}
}

/* CreateAuthorizationServerForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateAuthorizationServerForbidden struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerForbidden  %+v", 403, o.Payload)
}
func (o *CreateAuthorizationServerForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerNotFound creates a CreateAuthorizationServerNotFound with default headers values
func NewCreateAuthorizationServerNotFound() *CreateAuthorizationServerNotFound {
	return &CreateAuthorizationServerNotFound{}
}

/* CreateAuthorizationServerNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateAuthorizationServerNotFound struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerNotFound  %+v", 404, o.Payload)
}
func (o *CreateAuthorizationServerNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerConflict creates a CreateAuthorizationServerConflict with default headers values
func NewCreateAuthorizationServerConflict() *CreateAuthorizationServerConflict {
	return &CreateAuthorizationServerConflict{}
}

/* CreateAuthorizationServerConflict describes a response with status code 409, with default header values.

HttpError
*/
type CreateAuthorizationServerConflict struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerConflict) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerConflict  %+v", 409, o.Payload)
}
func (o *CreateAuthorizationServerConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerUnprocessableEntity creates a CreateAuthorizationServerUnprocessableEntity with default headers values
func NewCreateAuthorizationServerUnprocessableEntity() *CreateAuthorizationServerUnprocessableEntity {
	return &CreateAuthorizationServerUnprocessableEntity{}
}

/* CreateAuthorizationServerUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateAuthorizationServerUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateAuthorizationServerUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers][%d] createAuthorizationServerUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateAuthorizationServerUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
