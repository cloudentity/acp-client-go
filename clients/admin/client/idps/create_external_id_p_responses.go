// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// CreateExternalIDPReader is a Reader for the CreateExternalIDP structure.
type CreateExternalIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateExternalIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateExternalIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateExternalIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateExternalIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateExternalIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateExternalIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateExternalIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateExternalIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateExternalIDPCreated creates a CreateExternalIDPCreated with default headers values
func NewCreateExternalIDPCreated() *CreateExternalIDPCreated {
	return &CreateExternalIDPCreated{}
}

/* CreateExternalIDPCreated describes a response with status code 201, with default header values.

ExternalIDP
*/
type CreateExternalIDPCreated struct {
	Payload *models.ExternalIDP
}

func (o *CreateExternalIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPCreated  %+v", 201, o.Payload)
}
func (o *CreateExternalIDPCreated) GetPayload() *models.ExternalIDP {
	return o.Payload
}

func (o *CreateExternalIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ExternalIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPBadRequest creates a CreateExternalIDPBadRequest with default headers values
func NewCreateExternalIDPBadRequest() *CreateExternalIDPBadRequest {
	return &CreateExternalIDPBadRequest{}
}

/* CreateExternalIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateExternalIDPBadRequest struct {
	Payload *models.Error
}

func (o *CreateExternalIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPBadRequest  %+v", 400, o.Payload)
}
func (o *CreateExternalIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPUnauthorized creates a CreateExternalIDPUnauthorized with default headers values
func NewCreateExternalIDPUnauthorized() *CreateExternalIDPUnauthorized {
	return &CreateExternalIDPUnauthorized{}
}

/* CreateExternalIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateExternalIDPUnauthorized struct {
	Payload *models.Error
}

func (o *CreateExternalIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateExternalIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPForbidden creates a CreateExternalIDPForbidden with default headers values
func NewCreateExternalIDPForbidden() *CreateExternalIDPForbidden {
	return &CreateExternalIDPForbidden{}
}

/* CreateExternalIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateExternalIDPForbidden struct {
	Payload *models.Error
}

func (o *CreateExternalIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPForbidden  %+v", 403, o.Payload)
}
func (o *CreateExternalIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPNotFound creates a CreateExternalIDPNotFound with default headers values
func NewCreateExternalIDPNotFound() *CreateExternalIDPNotFound {
	return &CreateExternalIDPNotFound{}
}

/* CreateExternalIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateExternalIDPNotFound struct {
	Payload *models.Error
}

func (o *CreateExternalIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPNotFound  %+v", 404, o.Payload)
}
func (o *CreateExternalIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPUnprocessableEntity creates a CreateExternalIDPUnprocessableEntity with default headers values
func NewCreateExternalIDPUnprocessableEntity() *CreateExternalIDPUnprocessableEntity {
	return &CreateExternalIDPUnprocessableEntity{}
}

/* CreateExternalIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateExternalIDPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateExternalIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateExternalIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateExternalIDPTooManyRequests creates a CreateExternalIDPTooManyRequests with default headers values
func NewCreateExternalIDPTooManyRequests() *CreateExternalIDPTooManyRequests {
	return &CreateExternalIDPTooManyRequests{}
}

/* CreateExternalIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateExternalIDPTooManyRequests struct {
	Payload *models.Error
}

func (o *CreateExternalIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/external][%d] createExternalIdPTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateExternalIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateExternalIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
