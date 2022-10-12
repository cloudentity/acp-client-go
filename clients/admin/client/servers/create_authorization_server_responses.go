// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// CreateAuthorizationServerReader is a Reader for the CreateAuthorizationServer structure.
type CreateAuthorizationServerReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAuthorizationServerReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAuthorizationServerCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAuthorizationServerBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAuthorizationServerUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAuthorizationServerForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAuthorizationServerNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateAuthorizationServerConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAuthorizationServerUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAuthorizationServerTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateAuthorizationServerCreated creates a CreateAuthorizationServerCreated with default headers values
func NewCreateAuthorizationServerCreated() *CreateAuthorizationServerCreated {
	return &CreateAuthorizationServerCreated{}
}

/*
CreateAuthorizationServerCreated describes a response with status code 201, with default header values.

Server
*/
type CreateAuthorizationServerCreated struct {
	Payload *models.ServerResponse
}

// IsSuccess returns true when this create authorization server created response has a 2xx status code
func (o *CreateAuthorizationServerCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create authorization server created response has a 3xx status code
func (o *CreateAuthorizationServerCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server created response has a 4xx status code
func (o *CreateAuthorizationServerCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create authorization server created response has a 5xx status code
func (o *CreateAuthorizationServerCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server created response a status code equal to that given
func (o *CreateAuthorizationServerCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreateAuthorizationServerCreated) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerCreated  %+v", 201, o.Payload)
}

func (o *CreateAuthorizationServerCreated) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerCreated  %+v", 201, o.Payload)
}

func (o *CreateAuthorizationServerCreated) GetPayload() *models.ServerResponse {
	return o.Payload
}

func (o *CreateAuthorizationServerCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ServerResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerBadRequest creates a CreateAuthorizationServerBadRequest with default headers values
func NewCreateAuthorizationServerBadRequest() *CreateAuthorizationServerBadRequest {
	return &CreateAuthorizationServerBadRequest{}
}

/*
CreateAuthorizationServerBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type CreateAuthorizationServerBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server bad request response has a 2xx status code
func (o *CreateAuthorizationServerBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server bad request response has a 3xx status code
func (o *CreateAuthorizationServerBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server bad request response has a 4xx status code
func (o *CreateAuthorizationServerBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server bad request response has a 5xx status code
func (o *CreateAuthorizationServerBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server bad request response a status code equal to that given
func (o *CreateAuthorizationServerBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *CreateAuthorizationServerBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAuthorizationServerBadRequest) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerBadRequest  %+v", 400, o.Payload)
}

func (o *CreateAuthorizationServerBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerUnauthorized creates a CreateAuthorizationServerUnauthorized with default headers values
func NewCreateAuthorizationServerUnauthorized() *CreateAuthorizationServerUnauthorized {
	return &CreateAuthorizationServerUnauthorized{}
}

/*
CreateAuthorizationServerUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateAuthorizationServerUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server unauthorized response has a 2xx status code
func (o *CreateAuthorizationServerUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server unauthorized response has a 3xx status code
func (o *CreateAuthorizationServerUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server unauthorized response has a 4xx status code
func (o *CreateAuthorizationServerUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server unauthorized response has a 5xx status code
func (o *CreateAuthorizationServerUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server unauthorized response a status code equal to that given
func (o *CreateAuthorizationServerUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreateAuthorizationServerUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateAuthorizationServerUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateAuthorizationServerUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerForbidden creates a CreateAuthorizationServerForbidden with default headers values
func NewCreateAuthorizationServerForbidden() *CreateAuthorizationServerForbidden {
	return &CreateAuthorizationServerForbidden{}
}

/*
CreateAuthorizationServerForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateAuthorizationServerForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server forbidden response has a 2xx status code
func (o *CreateAuthorizationServerForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server forbidden response has a 3xx status code
func (o *CreateAuthorizationServerForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server forbidden response has a 4xx status code
func (o *CreateAuthorizationServerForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server forbidden response has a 5xx status code
func (o *CreateAuthorizationServerForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server forbidden response a status code equal to that given
func (o *CreateAuthorizationServerForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreateAuthorizationServerForbidden) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerForbidden  %+v", 403, o.Payload)
}

func (o *CreateAuthorizationServerForbidden) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerForbidden  %+v", 403, o.Payload)
}

func (o *CreateAuthorizationServerForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerNotFound creates a CreateAuthorizationServerNotFound with default headers values
func NewCreateAuthorizationServerNotFound() *CreateAuthorizationServerNotFound {
	return &CreateAuthorizationServerNotFound{}
}

/*
CreateAuthorizationServerNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateAuthorizationServerNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server not found response has a 2xx status code
func (o *CreateAuthorizationServerNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server not found response has a 3xx status code
func (o *CreateAuthorizationServerNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server not found response has a 4xx status code
func (o *CreateAuthorizationServerNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server not found response has a 5xx status code
func (o *CreateAuthorizationServerNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server not found response a status code equal to that given
func (o *CreateAuthorizationServerNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreateAuthorizationServerNotFound) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerNotFound  %+v", 404, o.Payload)
}

func (o *CreateAuthorizationServerNotFound) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerNotFound  %+v", 404, o.Payload)
}

func (o *CreateAuthorizationServerNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerConflict creates a CreateAuthorizationServerConflict with default headers values
func NewCreateAuthorizationServerConflict() *CreateAuthorizationServerConflict {
	return &CreateAuthorizationServerConflict{}
}

/*
CreateAuthorizationServerConflict describes a response with status code 409, with default header values.

HttpError
*/
type CreateAuthorizationServerConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server conflict response has a 2xx status code
func (o *CreateAuthorizationServerConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server conflict response has a 3xx status code
func (o *CreateAuthorizationServerConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server conflict response has a 4xx status code
func (o *CreateAuthorizationServerConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server conflict response has a 5xx status code
func (o *CreateAuthorizationServerConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server conflict response a status code equal to that given
func (o *CreateAuthorizationServerConflict) IsCode(code int) bool {
	return code == 409
}

func (o *CreateAuthorizationServerConflict) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerConflict  %+v", 409, o.Payload)
}

func (o *CreateAuthorizationServerConflict) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerConflict  %+v", 409, o.Payload)
}

func (o *CreateAuthorizationServerConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerUnprocessableEntity creates a CreateAuthorizationServerUnprocessableEntity with default headers values
func NewCreateAuthorizationServerUnprocessableEntity() *CreateAuthorizationServerUnprocessableEntity {
	return &CreateAuthorizationServerUnprocessableEntity{}
}

/*
CreateAuthorizationServerUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateAuthorizationServerUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server unprocessable entity response has a 2xx status code
func (o *CreateAuthorizationServerUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server unprocessable entity response has a 3xx status code
func (o *CreateAuthorizationServerUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server unprocessable entity response has a 4xx status code
func (o *CreateAuthorizationServerUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server unprocessable entity response has a 5xx status code
func (o *CreateAuthorizationServerUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server unprocessable entity response a status code equal to that given
func (o *CreateAuthorizationServerUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *CreateAuthorizationServerUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateAuthorizationServerUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateAuthorizationServerUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAuthorizationServerTooManyRequests creates a CreateAuthorizationServerTooManyRequests with default headers values
func NewCreateAuthorizationServerTooManyRequests() *CreateAuthorizationServerTooManyRequests {
	return &CreateAuthorizationServerTooManyRequests{}
}

/*
CreateAuthorizationServerTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateAuthorizationServerTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create authorization server too many requests response has a 2xx status code
func (o *CreateAuthorizationServerTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create authorization server too many requests response has a 3xx status code
func (o *CreateAuthorizationServerTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create authorization server too many requests response has a 4xx status code
func (o *CreateAuthorizationServerTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create authorization server too many requests response has a 5xx status code
func (o *CreateAuthorizationServerTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create authorization server too many requests response a status code equal to that given
func (o *CreateAuthorizationServerTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreateAuthorizationServerTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAuthorizationServerTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers][%d] createAuthorizationServerTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateAuthorizationServerTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAuthorizationServerTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
