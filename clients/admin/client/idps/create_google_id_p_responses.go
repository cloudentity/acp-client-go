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

// CreateGoogleIDPReader is a Reader for the CreateGoogleIDP structure.
type CreateGoogleIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateGoogleIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateGoogleIDPCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateGoogleIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateGoogleIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateGoogleIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateGoogleIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateGoogleIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateGoogleIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateGoogleIDPCreated creates a CreateGoogleIDPCreated with default headers values
func NewCreateGoogleIDPCreated() *CreateGoogleIDPCreated {
	return &CreateGoogleIDPCreated{}
}

/* CreateGoogleIDPCreated describes a response with status code 201, with default header values.

GoogleIDP
*/
type CreateGoogleIDPCreated struct {
	Payload *models.GoogleIDP
}

func (o *CreateGoogleIDPCreated) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPCreated  %+v", 201, o.Payload)
}
func (o *CreateGoogleIDPCreated) GetPayload() *models.GoogleIDP {
	return o.Payload
}

func (o *CreateGoogleIDPCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GoogleIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPBadRequest creates a CreateGoogleIDPBadRequest with default headers values
func NewCreateGoogleIDPBadRequest() *CreateGoogleIDPBadRequest {
	return &CreateGoogleIDPBadRequest{}
}

/* CreateGoogleIDPBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateGoogleIDPBadRequest struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPBadRequest  %+v", 400, o.Payload)
}
func (o *CreateGoogleIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPUnauthorized creates a CreateGoogleIDPUnauthorized with default headers values
func NewCreateGoogleIDPUnauthorized() *CreateGoogleIDPUnauthorized {
	return &CreateGoogleIDPUnauthorized{}
}

/* CreateGoogleIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateGoogleIDPUnauthorized struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *CreateGoogleIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPForbidden creates a CreateGoogleIDPForbidden with default headers values
func NewCreateGoogleIDPForbidden() *CreateGoogleIDPForbidden {
	return &CreateGoogleIDPForbidden{}
}

/* CreateGoogleIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateGoogleIDPForbidden struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPForbidden  %+v", 403, o.Payload)
}
func (o *CreateGoogleIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPNotFound creates a CreateGoogleIDPNotFound with default headers values
func NewCreateGoogleIDPNotFound() *CreateGoogleIDPNotFound {
	return &CreateGoogleIDPNotFound{}
}

/* CreateGoogleIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateGoogleIDPNotFound struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPNotFound  %+v", 404, o.Payload)
}
func (o *CreateGoogleIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPUnprocessableEntity creates a CreateGoogleIDPUnprocessableEntity with default headers values
func NewCreateGoogleIDPUnprocessableEntity() *CreateGoogleIDPUnprocessableEntity {
	return &CreateGoogleIDPUnprocessableEntity{}
}

/* CreateGoogleIDPUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateGoogleIDPUnprocessableEntity struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPUnprocessableEntity  %+v", 422, o.Payload)
}
func (o *CreateGoogleIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateGoogleIDPTooManyRequests creates a CreateGoogleIDPTooManyRequests with default headers values
func NewCreateGoogleIDPTooManyRequests() *CreateGoogleIDPTooManyRequests {
	return &CreateGoogleIDPTooManyRequests{}
}

/* CreateGoogleIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateGoogleIDPTooManyRequests struct {
	Payload *models.Error
}

func (o *CreateGoogleIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/idps/google][%d] createGoogleIdPTooManyRequests  %+v", 429, o.Payload)
}
func (o *CreateGoogleIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateGoogleIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
