// Code generated by go-swagger; DO NOT EDIT.

package claims

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// CreateClaimReader is a Reader for the CreateClaim structure.
type CreateClaimReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateClaimReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateClaimCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewCreateClaimUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateClaimForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateClaimNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateClaimConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateClaimUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateClaimTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateClaimCreated creates a CreateClaimCreated with default headers values
func NewCreateClaimCreated() *CreateClaimCreated {
	return &CreateClaimCreated{}
}

/*
CreateClaimCreated describes a response with status code 201, with default header values.

Claim
*/
type CreateClaimCreated struct {
	Payload *models.Claim
}

// IsSuccess returns true when this create claim created response has a 2xx status code
func (o *CreateClaimCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create claim created response has a 3xx status code
func (o *CreateClaimCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim created response has a 4xx status code
func (o *CreateClaimCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create claim created response has a 5xx status code
func (o *CreateClaimCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim created response a status code equal to that given
func (o *CreateClaimCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreateClaimCreated) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimCreated  %+v", 201, o.Payload)
}

func (o *CreateClaimCreated) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimCreated  %+v", 201, o.Payload)
}

func (o *CreateClaimCreated) GetPayload() *models.Claim {
	return o.Payload
}

func (o *CreateClaimCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Claim)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimUnauthorized creates a CreateClaimUnauthorized with default headers values
func NewCreateClaimUnauthorized() *CreateClaimUnauthorized {
	return &CreateClaimUnauthorized{}
}

/*
CreateClaimUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type CreateClaimUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim unauthorized response has a 2xx status code
func (o *CreateClaimUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim unauthorized response has a 3xx status code
func (o *CreateClaimUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim unauthorized response has a 4xx status code
func (o *CreateClaimUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim unauthorized response has a 5xx status code
func (o *CreateClaimUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim unauthorized response a status code equal to that given
func (o *CreateClaimUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreateClaimUnauthorized) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateClaimUnauthorized) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateClaimUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimForbidden creates a CreateClaimForbidden with default headers values
func NewCreateClaimForbidden() *CreateClaimForbidden {
	return &CreateClaimForbidden{}
}

/*
CreateClaimForbidden describes a response with status code 403, with default header values.

HttpError
*/
type CreateClaimForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim forbidden response has a 2xx status code
func (o *CreateClaimForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim forbidden response has a 3xx status code
func (o *CreateClaimForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim forbidden response has a 4xx status code
func (o *CreateClaimForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim forbidden response has a 5xx status code
func (o *CreateClaimForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim forbidden response a status code equal to that given
func (o *CreateClaimForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreateClaimForbidden) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimForbidden  %+v", 403, o.Payload)
}

func (o *CreateClaimForbidden) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimForbidden  %+v", 403, o.Payload)
}

func (o *CreateClaimForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimNotFound creates a CreateClaimNotFound with default headers values
func NewCreateClaimNotFound() *CreateClaimNotFound {
	return &CreateClaimNotFound{}
}

/*
CreateClaimNotFound describes a response with status code 404, with default header values.

HttpError
*/
type CreateClaimNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim not found response has a 2xx status code
func (o *CreateClaimNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim not found response has a 3xx status code
func (o *CreateClaimNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim not found response has a 4xx status code
func (o *CreateClaimNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim not found response has a 5xx status code
func (o *CreateClaimNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim not found response a status code equal to that given
func (o *CreateClaimNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreateClaimNotFound) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimNotFound  %+v", 404, o.Payload)
}

func (o *CreateClaimNotFound) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimNotFound  %+v", 404, o.Payload)
}

func (o *CreateClaimNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimConflict creates a CreateClaimConflict with default headers values
func NewCreateClaimConflict() *CreateClaimConflict {
	return &CreateClaimConflict{}
}

/*
CreateClaimConflict describes a response with status code 409, with default header values.

HttpError
*/
type CreateClaimConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim conflict response has a 2xx status code
func (o *CreateClaimConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim conflict response has a 3xx status code
func (o *CreateClaimConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim conflict response has a 4xx status code
func (o *CreateClaimConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim conflict response has a 5xx status code
func (o *CreateClaimConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim conflict response a status code equal to that given
func (o *CreateClaimConflict) IsCode(code int) bool {
	return code == 409
}

func (o *CreateClaimConflict) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimConflict  %+v", 409, o.Payload)
}

func (o *CreateClaimConflict) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimConflict  %+v", 409, o.Payload)
}

func (o *CreateClaimConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimUnprocessableEntity creates a CreateClaimUnprocessableEntity with default headers values
func NewCreateClaimUnprocessableEntity() *CreateClaimUnprocessableEntity {
	return &CreateClaimUnprocessableEntity{}
}

/*
CreateClaimUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type CreateClaimUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim unprocessable entity response has a 2xx status code
func (o *CreateClaimUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim unprocessable entity response has a 3xx status code
func (o *CreateClaimUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim unprocessable entity response has a 4xx status code
func (o *CreateClaimUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim unprocessable entity response has a 5xx status code
func (o *CreateClaimUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim unprocessable entity response a status code equal to that given
func (o *CreateClaimUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *CreateClaimUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateClaimUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateClaimUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateClaimTooManyRequests creates a CreateClaimTooManyRequests with default headers values
func NewCreateClaimTooManyRequests() *CreateClaimTooManyRequests {
	return &CreateClaimTooManyRequests{}
}

/*
CreateClaimTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type CreateClaimTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create claim too many requests response has a 2xx status code
func (o *CreateClaimTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create claim too many requests response has a 3xx status code
func (o *CreateClaimTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create claim too many requests response has a 4xx status code
func (o *CreateClaimTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create claim too many requests response has a 5xx status code
func (o *CreateClaimTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create claim too many requests response a status code equal to that given
func (o *CreateClaimTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreateClaimTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateClaimTooManyRequests) String() string {
	return fmt.Sprintf("[POST /claims][%d] createClaimTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateClaimTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateClaimTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
