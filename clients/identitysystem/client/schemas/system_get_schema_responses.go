// Code generated by go-swagger; DO NOT EDIT.

package schemas

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemGetSchemaReader is a Reader for the SystemGetSchema structure.
type SystemGetSchemaReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemGetSchemaReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemGetSchemaOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemGetSchemaUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemGetSchemaForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemGetSchemaNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewSystemGetSchemaPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemGetSchemaTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemGetSchemaOK creates a SystemGetSchemaOK with default headers values
func NewSystemGetSchemaOK() *SystemGetSchemaOK {
	return &SystemGetSchemaOK{}
}

/*
SystemGetSchemaOK describes a response with status code 200, with default header values.

Identity Schema
*/
type SystemGetSchemaOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Schema
}

// IsSuccess returns true when this system get schema o k response has a 2xx status code
func (o *SystemGetSchemaOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system get schema o k response has a 3xx status code
func (o *SystemGetSchemaOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema o k response has a 4xx status code
func (o *SystemGetSchemaOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system get schema o k response has a 5xx status code
func (o *SystemGetSchemaOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema o k response a status code equal to that given
func (o *SystemGetSchemaOK) IsCode(code int) bool {
	return code == 200
}

func (o *SystemGetSchemaOK) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaOK  %+v", 200, o.Payload)
}

func (o *SystemGetSchemaOK) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaOK  %+v", 200, o.Payload)
}

func (o *SystemGetSchemaOK) GetPayload() *models.Schema {
	return o.Payload
}

func (o *SystemGetSchemaOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Schema)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetSchemaUnauthorized creates a SystemGetSchemaUnauthorized with default headers values
func NewSystemGetSchemaUnauthorized() *SystemGetSchemaUnauthorized {
	return &SystemGetSchemaUnauthorized{}
}

/*
SystemGetSchemaUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SystemGetSchemaUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get schema unauthorized response has a 2xx status code
func (o *SystemGetSchemaUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get schema unauthorized response has a 3xx status code
func (o *SystemGetSchemaUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema unauthorized response has a 4xx status code
func (o *SystemGetSchemaUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get schema unauthorized response has a 5xx status code
func (o *SystemGetSchemaUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema unauthorized response a status code equal to that given
func (o *SystemGetSchemaUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemGetSchemaUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetSchemaUnauthorized) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetSchemaUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetSchemaUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetSchemaForbidden creates a SystemGetSchemaForbidden with default headers values
func NewSystemGetSchemaForbidden() *SystemGetSchemaForbidden {
	return &SystemGetSchemaForbidden{}
}

/*
SystemGetSchemaForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SystemGetSchemaForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get schema forbidden response has a 2xx status code
func (o *SystemGetSchemaForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get schema forbidden response has a 3xx status code
func (o *SystemGetSchemaForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema forbidden response has a 4xx status code
func (o *SystemGetSchemaForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get schema forbidden response has a 5xx status code
func (o *SystemGetSchemaForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema forbidden response a status code equal to that given
func (o *SystemGetSchemaForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemGetSchemaForbidden) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetSchemaForbidden) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetSchemaForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetSchemaForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetSchemaNotFound creates a SystemGetSchemaNotFound with default headers values
func NewSystemGetSchemaNotFound() *SystemGetSchemaNotFound {
	return &SystemGetSchemaNotFound{}
}

/*
SystemGetSchemaNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SystemGetSchemaNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get schema not found response has a 2xx status code
func (o *SystemGetSchemaNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get schema not found response has a 3xx status code
func (o *SystemGetSchemaNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema not found response has a 4xx status code
func (o *SystemGetSchemaNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get schema not found response has a 5xx status code
func (o *SystemGetSchemaNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema not found response a status code equal to that given
func (o *SystemGetSchemaNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemGetSchemaNotFound) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetSchemaNotFound) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetSchemaNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetSchemaNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetSchemaPreconditionFailed creates a SystemGetSchemaPreconditionFailed with default headers values
func NewSystemGetSchemaPreconditionFailed() *SystemGetSchemaPreconditionFailed {
	return &SystemGetSchemaPreconditionFailed{}
}

/*
SystemGetSchemaPreconditionFailed describes a response with status code 412, with default header values.

HttpError
*/
type SystemGetSchemaPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get schema precondition failed response has a 2xx status code
func (o *SystemGetSchemaPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get schema precondition failed response has a 3xx status code
func (o *SystemGetSchemaPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema precondition failed response has a 4xx status code
func (o *SystemGetSchemaPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get schema precondition failed response has a 5xx status code
func (o *SystemGetSchemaPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema precondition failed response a status code equal to that given
func (o *SystemGetSchemaPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

func (o *SystemGetSchemaPreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemGetSchemaPreconditionFailed) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaPreconditionFailed  %+v", 412, o.Payload)
}

func (o *SystemGetSchemaPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetSchemaPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetSchemaTooManyRequests creates a SystemGetSchemaTooManyRequests with default headers values
func NewSystemGetSchemaTooManyRequests() *SystemGetSchemaTooManyRequests {
	return &SystemGetSchemaTooManyRequests{}
}

/*
SystemGetSchemaTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SystemGetSchemaTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get schema too many requests response has a 2xx status code
func (o *SystemGetSchemaTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get schema too many requests response has a 3xx status code
func (o *SystemGetSchemaTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get schema too many requests response has a 4xx status code
func (o *SystemGetSchemaTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get schema too many requests response has a 5xx status code
func (o *SystemGetSchemaTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system get schema too many requests response a status code equal to that given
func (o *SystemGetSchemaTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemGetSchemaTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetSchemaTooManyRequests) String() string {
	return fmt.Sprintf("[GET /system/schemas/{schID}][%d] systemGetSchemaTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetSchemaTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetSchemaTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
