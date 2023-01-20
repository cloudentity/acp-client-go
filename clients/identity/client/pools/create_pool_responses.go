// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// CreatePoolReader is a Reader for the CreatePool structure.
type CreatePoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreatePoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreatePoolCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreatePoolBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreatePoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreatePoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreatePoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreatePoolConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreatePoolUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreatePoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreatePoolCreated creates a CreatePoolCreated with default headers values
func NewCreatePoolCreated() *CreatePoolCreated {
	return &CreatePoolCreated{}
}

/*
CreatePoolCreated describes a response with status code 201, with default header values.

Identity Pool
*/
type CreatePoolCreated struct {
	Payload *models.PoolResponse
}

// IsSuccess returns true when this create pool created response has a 2xx status code
func (o *CreatePoolCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create pool created response has a 3xx status code
func (o *CreatePoolCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool created response has a 4xx status code
func (o *CreatePoolCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create pool created response has a 5xx status code
func (o *CreatePoolCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool created response a status code equal to that given
func (o *CreatePoolCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreatePoolCreated) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolCreated  %+v", 201, o.Payload)
}

func (o *CreatePoolCreated) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolCreated  %+v", 201, o.Payload)
}

func (o *CreatePoolCreated) GetPayload() *models.PoolResponse {
	return o.Payload
}

func (o *CreatePoolCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PoolResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolBadRequest creates a CreatePoolBadRequest with default headers values
func NewCreatePoolBadRequest() *CreatePoolBadRequest {
	return &CreatePoolBadRequest{}
}

/*
CreatePoolBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreatePoolBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool bad request response has a 2xx status code
func (o *CreatePoolBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool bad request response has a 3xx status code
func (o *CreatePoolBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool bad request response has a 4xx status code
func (o *CreatePoolBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool bad request response has a 5xx status code
func (o *CreatePoolBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool bad request response a status code equal to that given
func (o *CreatePoolBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *CreatePoolBadRequest) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolBadRequest  %+v", 400, o.Payload)
}

func (o *CreatePoolBadRequest) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolBadRequest  %+v", 400, o.Payload)
}

func (o *CreatePoolBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolUnauthorized creates a CreatePoolUnauthorized with default headers values
func NewCreatePoolUnauthorized() *CreatePoolUnauthorized {
	return &CreatePoolUnauthorized{}
}

/*
CreatePoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreatePoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool unauthorized response has a 2xx status code
func (o *CreatePoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool unauthorized response has a 3xx status code
func (o *CreatePoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool unauthorized response has a 4xx status code
func (o *CreatePoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool unauthorized response has a 5xx status code
func (o *CreatePoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool unauthorized response a status code equal to that given
func (o *CreatePoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreatePoolUnauthorized) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *CreatePoolUnauthorized) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *CreatePoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolForbidden creates a CreatePoolForbidden with default headers values
func NewCreatePoolForbidden() *CreatePoolForbidden {
	return &CreatePoolForbidden{}
}

/*
CreatePoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreatePoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool forbidden response has a 2xx status code
func (o *CreatePoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool forbidden response has a 3xx status code
func (o *CreatePoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool forbidden response has a 4xx status code
func (o *CreatePoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool forbidden response has a 5xx status code
func (o *CreatePoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool forbidden response a status code equal to that given
func (o *CreatePoolForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreatePoolForbidden) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolForbidden  %+v", 403, o.Payload)
}

func (o *CreatePoolForbidden) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolForbidden  %+v", 403, o.Payload)
}

func (o *CreatePoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolNotFound creates a CreatePoolNotFound with default headers values
func NewCreatePoolNotFound() *CreatePoolNotFound {
	return &CreatePoolNotFound{}
}

/*
CreatePoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreatePoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool not found response has a 2xx status code
func (o *CreatePoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool not found response has a 3xx status code
func (o *CreatePoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool not found response has a 4xx status code
func (o *CreatePoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool not found response has a 5xx status code
func (o *CreatePoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool not found response a status code equal to that given
func (o *CreatePoolNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreatePoolNotFound) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolNotFound  %+v", 404, o.Payload)
}

func (o *CreatePoolNotFound) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolNotFound  %+v", 404, o.Payload)
}

func (o *CreatePoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolConflict creates a CreatePoolConflict with default headers values
func NewCreatePoolConflict() *CreatePoolConflict {
	return &CreatePoolConflict{}
}

/*
CreatePoolConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreatePoolConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool conflict response has a 2xx status code
func (o *CreatePoolConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool conflict response has a 3xx status code
func (o *CreatePoolConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool conflict response has a 4xx status code
func (o *CreatePoolConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool conflict response has a 5xx status code
func (o *CreatePoolConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool conflict response a status code equal to that given
func (o *CreatePoolConflict) IsCode(code int) bool {
	return code == 409
}

func (o *CreatePoolConflict) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolConflict  %+v", 409, o.Payload)
}

func (o *CreatePoolConflict) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolConflict  %+v", 409, o.Payload)
}

func (o *CreatePoolConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolUnprocessableEntity creates a CreatePoolUnprocessableEntity with default headers values
func NewCreatePoolUnprocessableEntity() *CreatePoolUnprocessableEntity {
	return &CreatePoolUnprocessableEntity{}
}

/*
CreatePoolUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreatePoolUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool unprocessable entity response has a 2xx status code
func (o *CreatePoolUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool unprocessable entity response has a 3xx status code
func (o *CreatePoolUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool unprocessable entity response has a 4xx status code
func (o *CreatePoolUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool unprocessable entity response has a 5xx status code
func (o *CreatePoolUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool unprocessable entity response a status code equal to that given
func (o *CreatePoolUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *CreatePoolUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreatePoolUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreatePoolUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePoolTooManyRequests creates a CreatePoolTooManyRequests with default headers values
func NewCreatePoolTooManyRequests() *CreatePoolTooManyRequests {
	return &CreatePoolTooManyRequests{}
}

/*
CreatePoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreatePoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create pool too many requests response has a 2xx status code
func (o *CreatePoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create pool too many requests response has a 3xx status code
func (o *CreatePoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create pool too many requests response has a 4xx status code
func (o *CreatePoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create pool too many requests response has a 5xx status code
func (o *CreatePoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create pool too many requests response a status code equal to that given
func (o *CreatePoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreatePoolTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePoolTooManyRequests) String() string {
	return fmt.Sprintf("[POST /admin/pools][%d] createPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreatePoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
