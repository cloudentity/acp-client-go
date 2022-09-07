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

// DeleteSchemaReader is a Reader for the DeleteSchema structure.
type DeleteSchemaReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteSchemaReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteSchemaNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteSchemaUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteSchemaForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteSchemaNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteSchemaConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteSchemaTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteSchemaNoContent creates a DeleteSchemaNoContent with default headers values
func NewDeleteSchemaNoContent() *DeleteSchemaNoContent {
	return &DeleteSchemaNoContent{}
}

/* DeleteSchemaNoContent describes a response with status code 204, with default header values.

Schema has been deleted
*/
type DeleteSchemaNoContent struct {
}

func (o *DeleteSchemaNoContent) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaNoContent ", 204)
}

func (o *DeleteSchemaNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteSchemaUnauthorized creates a DeleteSchemaUnauthorized with default headers values
func NewDeleteSchemaUnauthorized() *DeleteSchemaUnauthorized {
	return &DeleteSchemaUnauthorized{}
}

/* DeleteSchemaUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type DeleteSchemaUnauthorized struct {
	Payload *models.Error
}

func (o *DeleteSchemaUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaUnauthorized  %+v", 401, o.Payload)
}
func (o *DeleteSchemaUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteSchemaUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSchemaForbidden creates a DeleteSchemaForbidden with default headers values
func NewDeleteSchemaForbidden() *DeleteSchemaForbidden {
	return &DeleteSchemaForbidden{}
}

/* DeleteSchemaForbidden describes a response with status code 403, with default header values.

HttpError
*/
type DeleteSchemaForbidden struct {
	Payload *models.Error
}

func (o *DeleteSchemaForbidden) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaForbidden  %+v", 403, o.Payload)
}
func (o *DeleteSchemaForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteSchemaForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSchemaNotFound creates a DeleteSchemaNotFound with default headers values
func NewDeleteSchemaNotFound() *DeleteSchemaNotFound {
	return &DeleteSchemaNotFound{}
}

/* DeleteSchemaNotFound describes a response with status code 404, with default header values.

HttpError
*/
type DeleteSchemaNotFound struct {
	Payload *models.Error
}

func (o *DeleteSchemaNotFound) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaNotFound  %+v", 404, o.Payload)
}
func (o *DeleteSchemaNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteSchemaNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSchemaConflict creates a DeleteSchemaConflict with default headers values
func NewDeleteSchemaConflict() *DeleteSchemaConflict {
	return &DeleteSchemaConflict{}
}

/* DeleteSchemaConflict describes a response with status code 409, with default header values.

HttpError
*/
type DeleteSchemaConflict struct {
	Payload *models.Error
}

func (o *DeleteSchemaConflict) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaConflict  %+v", 409, o.Payload)
}
func (o *DeleteSchemaConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteSchemaConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteSchemaTooManyRequests creates a DeleteSchemaTooManyRequests with default headers values
func NewDeleteSchemaTooManyRequests() *DeleteSchemaTooManyRequests {
	return &DeleteSchemaTooManyRequests{}
}

/* DeleteSchemaTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type DeleteSchemaTooManyRequests struct {
	Payload *models.Error
}

func (o *DeleteSchemaTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /admin/schemas/{schID}][%d] deleteSchemaTooManyRequests  %+v", 429, o.Payload)
}
func (o *DeleteSchemaTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteSchemaTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
