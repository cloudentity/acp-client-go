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

// CreateAzureB2CIDPReader is a Reader for the CreateAzureB2CIDP structure.
type CreateAzureB2CIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAzureB2CIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAzureB2CIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAzureB2CIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAzureB2CIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAzureB2CIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAzureB2CIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAzureB2CIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAzureB2CIDPCreated creates a CreateAzureB2CIDPCreated with default headers values
func NewCreateAzureB2CIDPCreated() *CreateAzureB2CIDPCreated {
	return &CreateAzureB2CIDPCreated{}
}

/* CreateAzureB2CIDPCreated describes a response with status code 201, with default header values.

AzureB2CIDP
*/
type CreateAzureB2CIDPCreated struct {
	Payload *models.AzureB2CIDP
}

func (o *CreateAzureB2CIDPCreated) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPCreated  %+v", 201, o.Payload)
}
func (o *CreateAzureB2CIDPCreated) GetPayload() *models.AzureB2CIDP {
	return o.Payload
}

func (o *CreateAzureB2CIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureB2CIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPBadRequest creates a CreateAzureB2CIDPBadRequest with default headers values
func NewCreateAzureB2CIDPBadRequest() *CreateAzureB2CIDPBadRequest {
	return &CreateAzureB2CIDPBadRequest{}
}

/* CreateAzureB2CIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateAzureB2CIDPBadRequest struct {
	Payload *models.Error
}

func (o *CreateAzureB2CIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPBadRequest  %+v", 400, o.Payload)
}
func (o *CreateAzureB2CIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPUnauthorized creates a CreateAzureB2CIDPUnauthorized with default headers values
func NewCreateAzureB2CIDPUnauthorized() *CreateAzureB2CIDPUnauthorized {
	return &CreateAzureB2CIDPUnauthorized{}
}

/* CreateAzureB2CIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateAzureB2CIDPUnauthorized struct {
	Payload *models.Error
}

func (o *CreateAzureB2CIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateAzureB2CIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPForbidden creates a CreateAzureB2CIDPForbidden with default headers values
func NewCreateAzureB2CIDPForbidden() *CreateAzureB2CIDPForbidden {
	return &CreateAzureB2CIDPForbidden{}
}

/* CreateAzureB2CIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateAzureB2CIDPForbidden struct {
	Payload *models.Error
}

func (o *CreateAzureB2CIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPForbidden  %+v", 403, o.Payload)
}
func (o *CreateAzureB2CIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPNotFound creates a CreateAzureB2CIDPNotFound with default headers values
func NewCreateAzureB2CIDPNotFound() *CreateAzureB2CIDPNotFound {
	return &CreateAzureB2CIDPNotFound{}
}

/* CreateAzureB2CIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateAzureB2CIDPNotFound struct {
	Payload *models.Error
}

func (o *CreateAzureB2CIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPNotFound  %+v", 404, o.Payload)
}
func (o *CreateAzureB2CIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureB2CIDPUnprocessableEntity creates a CreateAzureB2CIDPUnprocessableEntity with default headers values
func NewCreateAzureB2CIDPUnprocessableEntity() *CreateAzureB2CIDPUnprocessableEntity {
	return &CreateAzureB2CIDPUnprocessableEntity{}
}

/* CreateAzureB2CIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateAzureB2CIDPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateAzureB2CIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azureb2c][%d] createAzureB2CIdPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateAzureB2CIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureB2CIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}