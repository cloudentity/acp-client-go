// Code generated by go-swagger; DO NOT EDIT.

package schemas

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemUpdateSchemaReader is a Reader for the SystemUpdateSchema structure.
type SystemUpdateSchemaReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemUpdateSchemaReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemUpdateSchemaOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemUpdateSchemaBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemUpdateSchemaUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemUpdateSchemaForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemUpdateSchemaNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSystemUpdateSchemaConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemUpdateSchemaUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemUpdateSchemaTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /system/schemas/{schID}] systemUpdateSchema", response, response.Code())
	}
}

// NewSystemUpdateSchemaOK creates a SystemUpdateSchemaOK with default headers values
func NewSystemUpdateSchemaOK() *SystemUpdateSchemaOK {
	return &SystemUpdateSchemaOK{}
}

/*
SystemUpdateSchemaOK describes a response with status code 200, with default header values.

Schema
*/
type SystemUpdateSchemaOK struct {
	Payload *models.Schema
}

// IsSuccess returns true when this system update schema o k response has a 2xx status code
func (o *SystemUpdateSchemaOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system update schema o k response has a 3xx status code
func (o *SystemUpdateSchemaOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema o k response has a 4xx status code
func (o *SystemUpdateSchemaOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system update schema o k response has a 5xx status code
func (o *SystemUpdateSchemaOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema o k response a status code equal to that given
func (o *SystemUpdateSchemaOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the system update schema o k response
func (o *SystemUpdateSchemaOK) Code() int {
	return 200
}

func (o *SystemUpdateSchemaOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaOK %s", 200, payload)
}

func (o *SystemUpdateSchemaOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaOK %s", 200, payload)
}

func (o *SystemUpdateSchemaOK) GetPayload() *models.Schema {
	return o.Payload
}

func (o *SystemUpdateSchemaOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Schema)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaBadRequest creates a SystemUpdateSchemaBadRequest with default headers values
func NewSystemUpdateSchemaBadRequest() *SystemUpdateSchemaBadRequest {
	return &SystemUpdateSchemaBadRequest{}
}

/*
SystemUpdateSchemaBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SystemUpdateSchemaBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema bad request response has a 2xx status code
func (o *SystemUpdateSchemaBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema bad request response has a 3xx status code
func (o *SystemUpdateSchemaBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema bad request response has a 4xx status code
func (o *SystemUpdateSchemaBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema bad request response has a 5xx status code
func (o *SystemUpdateSchemaBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema bad request response a status code equal to that given
func (o *SystemUpdateSchemaBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the system update schema bad request response
func (o *SystemUpdateSchemaBadRequest) Code() int {
	return 400
}

func (o *SystemUpdateSchemaBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaBadRequest %s", 400, payload)
}

func (o *SystemUpdateSchemaBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaBadRequest %s", 400, payload)
}

func (o *SystemUpdateSchemaBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaUnauthorized creates a SystemUpdateSchemaUnauthorized with default headers values
func NewSystemUpdateSchemaUnauthorized() *SystemUpdateSchemaUnauthorized {
	return &SystemUpdateSchemaUnauthorized{}
}

/*
SystemUpdateSchemaUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemUpdateSchemaUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema unauthorized response has a 2xx status code
func (o *SystemUpdateSchemaUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema unauthorized response has a 3xx status code
func (o *SystemUpdateSchemaUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema unauthorized response has a 4xx status code
func (o *SystemUpdateSchemaUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema unauthorized response has a 5xx status code
func (o *SystemUpdateSchemaUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema unauthorized response a status code equal to that given
func (o *SystemUpdateSchemaUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system update schema unauthorized response
func (o *SystemUpdateSchemaUnauthorized) Code() int {
	return 401
}

func (o *SystemUpdateSchemaUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaUnauthorized %s", 401, payload)
}

func (o *SystemUpdateSchemaUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaUnauthorized %s", 401, payload)
}

func (o *SystemUpdateSchemaUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaForbidden creates a SystemUpdateSchemaForbidden with default headers values
func NewSystemUpdateSchemaForbidden() *SystemUpdateSchemaForbidden {
	return &SystemUpdateSchemaForbidden{}
}

/*
SystemUpdateSchemaForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemUpdateSchemaForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema forbidden response has a 2xx status code
func (o *SystemUpdateSchemaForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema forbidden response has a 3xx status code
func (o *SystemUpdateSchemaForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema forbidden response has a 4xx status code
func (o *SystemUpdateSchemaForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema forbidden response has a 5xx status code
func (o *SystemUpdateSchemaForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema forbidden response a status code equal to that given
func (o *SystemUpdateSchemaForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system update schema forbidden response
func (o *SystemUpdateSchemaForbidden) Code() int {
	return 403
}

func (o *SystemUpdateSchemaForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaForbidden %s", 403, payload)
}

func (o *SystemUpdateSchemaForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaForbidden %s", 403, payload)
}

func (o *SystemUpdateSchemaForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaNotFound creates a SystemUpdateSchemaNotFound with default headers values
func NewSystemUpdateSchemaNotFound() *SystemUpdateSchemaNotFound {
	return &SystemUpdateSchemaNotFound{}
}

/*
SystemUpdateSchemaNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemUpdateSchemaNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema not found response has a 2xx status code
func (o *SystemUpdateSchemaNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema not found response has a 3xx status code
func (o *SystemUpdateSchemaNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema not found response has a 4xx status code
func (o *SystemUpdateSchemaNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema not found response has a 5xx status code
func (o *SystemUpdateSchemaNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema not found response a status code equal to that given
func (o *SystemUpdateSchemaNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the system update schema not found response
func (o *SystemUpdateSchemaNotFound) Code() int {
	return 404
}

func (o *SystemUpdateSchemaNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaNotFound %s", 404, payload)
}

func (o *SystemUpdateSchemaNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaNotFound %s", 404, payload)
}

func (o *SystemUpdateSchemaNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaConflict creates a SystemUpdateSchemaConflict with default headers values
func NewSystemUpdateSchemaConflict() *SystemUpdateSchemaConflict {
	return &SystemUpdateSchemaConflict{}
}

/*
SystemUpdateSchemaConflict describes a response with status code 409, with default header values.

Conflict
*/
type SystemUpdateSchemaConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema conflict response has a 2xx status code
func (o *SystemUpdateSchemaConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema conflict response has a 3xx status code
func (o *SystemUpdateSchemaConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema conflict response has a 4xx status code
func (o *SystemUpdateSchemaConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema conflict response has a 5xx status code
func (o *SystemUpdateSchemaConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema conflict response a status code equal to that given
func (o *SystemUpdateSchemaConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the system update schema conflict response
func (o *SystemUpdateSchemaConflict) Code() int {
	return 409
}

func (o *SystemUpdateSchemaConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaConflict %s", 409, payload)
}

func (o *SystemUpdateSchemaConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaConflict %s", 409, payload)
}

func (o *SystemUpdateSchemaConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaUnprocessableEntity creates a SystemUpdateSchemaUnprocessableEntity with default headers values
func NewSystemUpdateSchemaUnprocessableEntity() *SystemUpdateSchemaUnprocessableEntity {
	return &SystemUpdateSchemaUnprocessableEntity{}
}

/*
SystemUpdateSchemaUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SystemUpdateSchemaUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema unprocessable entity response has a 2xx status code
func (o *SystemUpdateSchemaUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema unprocessable entity response has a 3xx status code
func (o *SystemUpdateSchemaUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema unprocessable entity response has a 4xx status code
func (o *SystemUpdateSchemaUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema unprocessable entity response has a 5xx status code
func (o *SystemUpdateSchemaUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema unprocessable entity response a status code equal to that given
func (o *SystemUpdateSchemaUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the system update schema unprocessable entity response
func (o *SystemUpdateSchemaUnprocessableEntity) Code() int {
	return 422
}

func (o *SystemUpdateSchemaUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaUnprocessableEntity %s", 422, payload)
}

func (o *SystemUpdateSchemaUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaUnprocessableEntity %s", 422, payload)
}

func (o *SystemUpdateSchemaUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdateSchemaTooManyRequests creates a SystemUpdateSchemaTooManyRequests with default headers values
func NewSystemUpdateSchemaTooManyRequests() *SystemUpdateSchemaTooManyRequests {
	return &SystemUpdateSchemaTooManyRequests{}
}

/*
SystemUpdateSchemaTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemUpdateSchemaTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update schema too many requests response has a 2xx status code
func (o *SystemUpdateSchemaTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update schema too many requests response has a 3xx status code
func (o *SystemUpdateSchemaTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update schema too many requests response has a 4xx status code
func (o *SystemUpdateSchemaTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update schema too many requests response has a 5xx status code
func (o *SystemUpdateSchemaTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system update schema too many requests response a status code equal to that given
func (o *SystemUpdateSchemaTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system update schema too many requests response
func (o *SystemUpdateSchemaTooManyRequests) Code() int {
	return 429
}

func (o *SystemUpdateSchemaTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaTooManyRequests %s", 429, payload)
}

func (o *SystemUpdateSchemaTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/schemas/{schID}][%d] systemUpdateSchemaTooManyRequests %s", 429, payload)
}

func (o *SystemUpdateSchemaTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdateSchemaTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
