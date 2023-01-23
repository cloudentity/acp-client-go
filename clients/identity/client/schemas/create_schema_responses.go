// Code generated by go-swagger; DO NOT EDIT.

package schemas

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// CreateSchemaReader is a Reader for the CreateSchema structure.
type CreateSchemaReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateSchemaReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateSchemaCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateSchemaBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateSchemaUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateSchemaForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateSchemaNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateSchemaConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateSchemaUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateSchemaTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateSchemaCreated creates a CreateSchemaCreated with default headers values
func NewCreateSchemaCreated() *CreateSchemaCreated {
	return &CreateSchemaCreated{}
}

/*
CreateSchemaCreated describes a response with status code 201, with default header values.

Schema
*/
type CreateSchemaCreated struct {
	Payload *models.Schema
}

// IsSuccess returns true when this create schema created response has a 2xx status code
func (o *CreateSchemaCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create schema created response has a 3xx status code
func (o *CreateSchemaCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema created response has a 4xx status code
func (o *CreateSchemaCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create schema created response has a 5xx status code
func (o *CreateSchemaCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema created response a status code equal to that given
func (o *CreateSchemaCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreateSchemaCreated) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaCreated  %+v", 201, o.Payload)
}

func (o *CreateSchemaCreated) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaCreated  %+v", 201, o.Payload)
}

func (o *CreateSchemaCreated) GetPayload() *models.Schema {
	return o.Payload
}

func (o *CreateSchemaCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Schema)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaBadRequest creates a CreateSchemaBadRequest with default headers values
func NewCreateSchemaBadRequest() *CreateSchemaBadRequest {
	return &CreateSchemaBadRequest{}
}

/*
CreateSchemaBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateSchemaBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema bad request response has a 2xx status code
func (o *CreateSchemaBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema bad request response has a 3xx status code
func (o *CreateSchemaBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema bad request response has a 4xx status code
func (o *CreateSchemaBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema bad request response has a 5xx status code
func (o *CreateSchemaBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema bad request response a status code equal to that given
func (o *CreateSchemaBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *CreateSchemaBadRequest) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaBadRequest  %+v", 400, o.Payload)
}

func (o *CreateSchemaBadRequest) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaBadRequest  %+v", 400, o.Payload)
}

func (o *CreateSchemaBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaUnauthorized creates a CreateSchemaUnauthorized with default headers values
func NewCreateSchemaUnauthorized() *CreateSchemaUnauthorized {
	return &CreateSchemaUnauthorized{}
}

/*
CreateSchemaUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateSchemaUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema unauthorized response has a 2xx status code
func (o *CreateSchemaUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema unauthorized response has a 3xx status code
func (o *CreateSchemaUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema unauthorized response has a 4xx status code
func (o *CreateSchemaUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema unauthorized response has a 5xx status code
func (o *CreateSchemaUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema unauthorized response a status code equal to that given
func (o *CreateSchemaUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreateSchemaUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateSchemaUnauthorized) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateSchemaUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaForbidden creates a CreateSchemaForbidden with default headers values
func NewCreateSchemaForbidden() *CreateSchemaForbidden {
	return &CreateSchemaForbidden{}
}

/*
CreateSchemaForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateSchemaForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema forbidden response has a 2xx status code
func (o *CreateSchemaForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema forbidden response has a 3xx status code
func (o *CreateSchemaForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema forbidden response has a 4xx status code
func (o *CreateSchemaForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema forbidden response has a 5xx status code
func (o *CreateSchemaForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema forbidden response a status code equal to that given
func (o *CreateSchemaForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreateSchemaForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaForbidden  %+v", 403, o.Payload)
}

func (o *CreateSchemaForbidden) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaForbidden  %+v", 403, o.Payload)
}

func (o *CreateSchemaForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaNotFound creates a CreateSchemaNotFound with default headers values
func NewCreateSchemaNotFound() *CreateSchemaNotFound {
	return &CreateSchemaNotFound{}
}

/*
CreateSchemaNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateSchemaNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema not found response has a 2xx status code
func (o *CreateSchemaNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema not found response has a 3xx status code
func (o *CreateSchemaNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema not found response has a 4xx status code
func (o *CreateSchemaNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema not found response has a 5xx status code
func (o *CreateSchemaNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema not found response a status code equal to that given
func (o *CreateSchemaNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreateSchemaNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaNotFound  %+v", 404, o.Payload)
}

func (o *CreateSchemaNotFound) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaNotFound  %+v", 404, o.Payload)
}

func (o *CreateSchemaNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaConflict creates a CreateSchemaConflict with default headers values
func NewCreateSchemaConflict() *CreateSchemaConflict {
	return &CreateSchemaConflict{}
}

/*
CreateSchemaConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreateSchemaConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema conflict response has a 2xx status code
func (o *CreateSchemaConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema conflict response has a 3xx status code
func (o *CreateSchemaConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema conflict response has a 4xx status code
func (o *CreateSchemaConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema conflict response has a 5xx status code
func (o *CreateSchemaConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema conflict response a status code equal to that given
func (o *CreateSchemaConflict) IsCode(code int) bool {
	return code == 409
}

func (o *CreateSchemaConflict) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaConflict  %+v", 409, o.Payload)
}

func (o *CreateSchemaConflict) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaConflict  %+v", 409, o.Payload)
}

func (o *CreateSchemaConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaUnprocessableEntity creates a CreateSchemaUnprocessableEntity with default headers values
func NewCreateSchemaUnprocessableEntity() *CreateSchemaUnprocessableEntity {
	return &CreateSchemaUnprocessableEntity{}
}

/*
CreateSchemaUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateSchemaUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema unprocessable entity response has a 2xx status code
func (o *CreateSchemaUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema unprocessable entity response has a 3xx status code
func (o *CreateSchemaUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema unprocessable entity response has a 4xx status code
func (o *CreateSchemaUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema unprocessable entity response has a 5xx status code
func (o *CreateSchemaUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema unprocessable entity response a status code equal to that given
func (o *CreateSchemaUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *CreateSchemaUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateSchemaUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateSchemaUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSchemaTooManyRequests creates a CreateSchemaTooManyRequests with default headers values
func NewCreateSchemaTooManyRequests() *CreateSchemaTooManyRequests {
	return &CreateSchemaTooManyRequests{}
}

/*
CreateSchemaTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateSchemaTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create schema too many requests response has a 2xx status code
func (o *CreateSchemaTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create schema too many requests response has a 3xx status code
func (o *CreateSchemaTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create schema too many requests response has a 4xx status code
func (o *CreateSchemaTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create schema too many requests response has a 5xx status code
func (o *CreateSchemaTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create schema too many requests response a status code equal to that given
func (o *CreateSchemaTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreateSchemaTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateSchemaTooManyRequests) String() string {
	return fmt.Sprintf("[POST /admin/schemas][%d] createSchemaTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateSchemaTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSchemaTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
