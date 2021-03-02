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

// CreateAzureIDPReader is a Reader for the CreateAzureIDP structure.
type CreateAzureIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAzureIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAzureIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAzureIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAzureIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAzureIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAzureIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAzureIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAzureIDPCreated creates a CreateAzureIDPCreated with default headers values
func NewCreateAzureIDPCreated() *CreateAzureIDPCreated {
	return &CreateAzureIDPCreated{}
}

/* CreateAzureIDPCreated describes a response with status code 201, with default header values.

AzureIDP
*/
type CreateAzureIDPCreated struct {
	Payload *models.AzureIDP
}

func (o *CreateAzureIDPCreated) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPCreated  %+v", 201, o.Payload)
}
func (o *CreateAzureIDPCreated) GetPayload() *models.AzureIDP {
	return o.Payload
}

func (o *CreateAzureIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPBadRequest creates a CreateAzureIDPBadRequest with default headers values
func NewCreateAzureIDPBadRequest() *CreateAzureIDPBadRequest {
	return &CreateAzureIDPBadRequest{}
}

/* CreateAzureIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateAzureIDPBadRequest struct {
	Payload *models.Error
}

func (o *CreateAzureIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPBadRequest  %+v", 400, o.Payload)
}
func (o *CreateAzureIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPUnauthorized creates a CreateAzureIDPUnauthorized with default headers values
func NewCreateAzureIDPUnauthorized() *CreateAzureIDPUnauthorized {
	return &CreateAzureIDPUnauthorized{}
}

/* CreateAzureIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateAzureIDPUnauthorized struct {
	Payload *models.Error
}

func (o *CreateAzureIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateAzureIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPForbidden creates a CreateAzureIDPForbidden with default headers values
func NewCreateAzureIDPForbidden() *CreateAzureIDPForbidden {
	return &CreateAzureIDPForbidden{}
}

/* CreateAzureIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateAzureIDPForbidden struct {
	Payload *models.Error
}

func (o *CreateAzureIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPForbidden  %+v", 403, o.Payload)
}
func (o *CreateAzureIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPNotFound creates a CreateAzureIDPNotFound with default headers values
func NewCreateAzureIDPNotFound() *CreateAzureIDPNotFound {
	return &CreateAzureIDPNotFound{}
}

/* CreateAzureIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateAzureIDPNotFound struct {
	Payload *models.Error
}

func (o *CreateAzureIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPNotFound  %+v", 404, o.Payload)
}
func (o *CreateAzureIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAzureIDPUnprocessableEntity creates a CreateAzureIDPUnprocessableEntity with default headers values
func NewCreateAzureIDPUnprocessableEntity() *CreateAzureIDPUnprocessableEntity {
	return &CreateAzureIDPUnprocessableEntity{}
}

/* CreateAzureIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateAzureIDPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateAzureIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/{tid}/servers/{aid}/idps/azure][%d] createAzureIdPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateAzureIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAzureIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
