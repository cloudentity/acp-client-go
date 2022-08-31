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

// ListSchemasReader is a Reader for the ListSchemas structure.
type ListSchemasReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListSchemasReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListSchemasOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListSchemasUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListSchemasForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListSchemasTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListSchemasOK creates a ListSchemasOK with default headers values
func NewListSchemasOK() *ListSchemasOK {
	return &ListSchemasOK{}
}

/* ListSchemasOK describes a response with status code 200, with default header values.

Schemas
*/
type ListSchemasOK struct {
	Payload *models.Schemas
}

func (o *ListSchemasOK) Error() string {
	return fmt.Sprintf("[GET /admin/schemas][%d] listSchemasOK  %+v", 200, o.Payload)
}
func (o *ListSchemasOK) GetPayload() *models.Schemas {
	return o.Payload
}

func (o *ListSchemasOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Schemas)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSchemasUnauthorized creates a ListSchemasUnauthorized with default headers values
func NewListSchemasUnauthorized() *ListSchemasUnauthorized {
	return &ListSchemasUnauthorized{}
}

/* ListSchemasUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListSchemasUnauthorized struct {
	Payload *models.Error
}

func (o *ListSchemasUnauthorized) Error() string {
	return fmt.Sprintf("[GET /admin/schemas][%d] listSchemasUnauthorized  %+v", 401, o.Payload)
}
func (o *ListSchemasUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSchemasUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSchemasForbidden creates a ListSchemasForbidden with default headers values
func NewListSchemasForbidden() *ListSchemasForbidden {
	return &ListSchemasForbidden{}
}

/* ListSchemasForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListSchemasForbidden struct {
	Payload *models.Error
}

func (o *ListSchemasForbidden) Error() string {
	return fmt.Sprintf("[GET /admin/schemas][%d] listSchemasForbidden  %+v", 403, o.Payload)
}
func (o *ListSchemasForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSchemasForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListSchemasTooManyRequests creates a ListSchemasTooManyRequests with default headers values
func NewListSchemasTooManyRequests() *ListSchemasTooManyRequests {
	return &ListSchemasTooManyRequests{}
}

/* ListSchemasTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListSchemasTooManyRequests struct {
	Payload *models.Error
}

func (o *ListSchemasTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /admin/schemas][%d] listSchemasTooManyRequests  %+v", 429, o.Payload)
}
func (o *ListSchemasTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListSchemasTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}