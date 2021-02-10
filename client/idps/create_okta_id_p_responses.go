// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// CreateOktaIDPReader is a Reader for the CreateOktaIDP structure.
type CreateOktaIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateOktaIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateOktaIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateOktaIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateOktaIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateOktaIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateOktaIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateOktaIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateOktaIDPCreated creates a CreateOktaIDPCreated with default headers values
func NewCreateOktaIDPCreated() *CreateOktaIDPCreated {
	return &CreateOktaIDPCreated{}
}

/* CreateOktaIDPCreated describes a response with status code 201, with default header values.

OktaIDP
*/
type CreateOktaIDPCreated struct {
	Payload *models.OktaIDP
}

func (o *CreateOktaIDPCreated) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPCreated  %+v", 201, o.Payload)
}
func (o *CreateOktaIDPCreated) GetPayload() *models.OktaIDP {
	return o.Payload
}

func (o *CreateOktaIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OktaIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOktaIDPBadRequest creates a CreateOktaIDPBadRequest with default headers values
func NewCreateOktaIDPBadRequest() *CreateOktaIDPBadRequest {
	return &CreateOktaIDPBadRequest{}
}

/* CreateOktaIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateOktaIDPBadRequest struct {
	Payload *models.Error
}

func (o *CreateOktaIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPBadRequest  %+v", 400, o.Payload)
}
func (o *CreateOktaIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOktaIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOktaIDPUnauthorized creates a CreateOktaIDPUnauthorized with default headers values
func NewCreateOktaIDPUnauthorized() *CreateOktaIDPUnauthorized {
	return &CreateOktaIDPUnauthorized{}
}

/* CreateOktaIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateOktaIDPUnauthorized struct {
	Payload *models.Error
}

func (o *CreateOktaIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateOktaIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOktaIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOktaIDPForbidden creates a CreateOktaIDPForbidden with default headers values
func NewCreateOktaIDPForbidden() *CreateOktaIDPForbidden {
	return &CreateOktaIDPForbidden{}
}

/* CreateOktaIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateOktaIDPForbidden struct {
	Payload *models.Error
}

func (o *CreateOktaIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPForbidden  %+v", 403, o.Payload)
}
func (o *CreateOktaIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOktaIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOktaIDPNotFound creates a CreateOktaIDPNotFound with default headers values
func NewCreateOktaIDPNotFound() *CreateOktaIDPNotFound {
	return &CreateOktaIDPNotFound{}
}

/* CreateOktaIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateOktaIDPNotFound struct {
	Payload *models.Error
}

func (o *CreateOktaIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPNotFound  %+v", 404, o.Payload)
}
func (o *CreateOktaIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOktaIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateOktaIDPUnprocessableEntity creates a CreateOktaIDPUnprocessableEntity with default headers values
func NewCreateOktaIDPUnprocessableEntity() *CreateOktaIDPUnprocessableEntity {
	return &CreateOktaIDPUnprocessableEntity{}
}

/* CreateOktaIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateOktaIDPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateOktaIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/okta][%d] createOktaIdPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateOktaIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateOktaIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
