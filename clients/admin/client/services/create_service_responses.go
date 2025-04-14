// Code generated by go-swagger; DO NOT EDIT.

package services

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// CreateServiceReader is a Reader for the CreateService structure.
type CreateServiceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateServiceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateServiceCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateServiceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateServiceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateServiceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateServiceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateServiceConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateServiceUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateServiceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /services] createService", response, response.Code())
	}
}

// NewCreateServiceCreated creates a CreateServiceCreated with default headers values
func NewCreateServiceCreated() *CreateServiceCreated {
	return &CreateServiceCreated{}
}

/*
CreateServiceCreated describes a response with status code 201, with default header values.

Service
*/
type CreateServiceCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ServiceWithAudience
}

// IsSuccess returns true when this create service created response has a 2xx status code
func (o *CreateServiceCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create service created response has a 3xx status code
func (o *CreateServiceCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service created response has a 4xx status code
func (o *CreateServiceCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create service created response has a 5xx status code
func (o *CreateServiceCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create service created response a status code equal to that given
func (o *CreateServiceCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create service created response
func (o *CreateServiceCreated) Code() int {
	return 201
}

func (o *CreateServiceCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceCreated %s", 201, payload)
}

func (o *CreateServiceCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceCreated %s", 201, payload)
}

func (o *CreateServiceCreated) GetPayload() *models.ServiceWithAudience {
	return o.Payload
}

func (o *CreateServiceCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ServiceWithAudience)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceBadRequest creates a CreateServiceBadRequest with default headers values
func NewCreateServiceBadRequest() *CreateServiceBadRequest {
	return &CreateServiceBadRequest{}
}

/*
CreateServiceBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateServiceBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service bad request response has a 2xx status code
func (o *CreateServiceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service bad request response has a 3xx status code
func (o *CreateServiceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service bad request response has a 4xx status code
func (o *CreateServiceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service bad request response has a 5xx status code
func (o *CreateServiceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create service bad request response a status code equal to that given
func (o *CreateServiceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create service bad request response
func (o *CreateServiceBadRequest) Code() int {
	return 400
}

func (o *CreateServiceBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceBadRequest %s", 400, payload)
}

func (o *CreateServiceBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceBadRequest %s", 400, payload)
}

func (o *CreateServiceBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceUnauthorized creates a CreateServiceUnauthorized with default headers values
func NewCreateServiceUnauthorized() *CreateServiceUnauthorized {
	return &CreateServiceUnauthorized{}
}

/*
CreateServiceUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateServiceUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service unauthorized response has a 2xx status code
func (o *CreateServiceUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service unauthorized response has a 3xx status code
func (o *CreateServiceUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service unauthorized response has a 4xx status code
func (o *CreateServiceUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service unauthorized response has a 5xx status code
func (o *CreateServiceUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create service unauthorized response a status code equal to that given
func (o *CreateServiceUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create service unauthorized response
func (o *CreateServiceUnauthorized) Code() int {
	return 401
}

func (o *CreateServiceUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceUnauthorized %s", 401, payload)
}

func (o *CreateServiceUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceUnauthorized %s", 401, payload)
}

func (o *CreateServiceUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceForbidden creates a CreateServiceForbidden with default headers values
func NewCreateServiceForbidden() *CreateServiceForbidden {
	return &CreateServiceForbidden{}
}

/*
CreateServiceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateServiceForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service forbidden response has a 2xx status code
func (o *CreateServiceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service forbidden response has a 3xx status code
func (o *CreateServiceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service forbidden response has a 4xx status code
func (o *CreateServiceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service forbidden response has a 5xx status code
func (o *CreateServiceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create service forbidden response a status code equal to that given
func (o *CreateServiceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create service forbidden response
func (o *CreateServiceForbidden) Code() int {
	return 403
}

func (o *CreateServiceForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceForbidden %s", 403, payload)
}

func (o *CreateServiceForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceForbidden %s", 403, payload)
}

func (o *CreateServiceForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceNotFound creates a CreateServiceNotFound with default headers values
func NewCreateServiceNotFound() *CreateServiceNotFound {
	return &CreateServiceNotFound{}
}

/*
CreateServiceNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateServiceNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service not found response has a 2xx status code
func (o *CreateServiceNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service not found response has a 3xx status code
func (o *CreateServiceNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service not found response has a 4xx status code
func (o *CreateServiceNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service not found response has a 5xx status code
func (o *CreateServiceNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create service not found response a status code equal to that given
func (o *CreateServiceNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create service not found response
func (o *CreateServiceNotFound) Code() int {
	return 404
}

func (o *CreateServiceNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceNotFound %s", 404, payload)
}

func (o *CreateServiceNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceNotFound %s", 404, payload)
}

func (o *CreateServiceNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceConflict creates a CreateServiceConflict with default headers values
func NewCreateServiceConflict() *CreateServiceConflict {
	return &CreateServiceConflict{}
}

/*
CreateServiceConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreateServiceConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service conflict response has a 2xx status code
func (o *CreateServiceConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service conflict response has a 3xx status code
func (o *CreateServiceConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service conflict response has a 4xx status code
func (o *CreateServiceConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service conflict response has a 5xx status code
func (o *CreateServiceConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create service conflict response a status code equal to that given
func (o *CreateServiceConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the create service conflict response
func (o *CreateServiceConflict) Code() int {
	return 409
}

func (o *CreateServiceConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceConflict %s", 409, payload)
}

func (o *CreateServiceConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceConflict %s", 409, payload)
}

func (o *CreateServiceConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceUnprocessableEntity creates a CreateServiceUnprocessableEntity with default headers values
func NewCreateServiceUnprocessableEntity() *CreateServiceUnprocessableEntity {
	return &CreateServiceUnprocessableEntity{}
}

/*
CreateServiceUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateServiceUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service unprocessable entity response has a 2xx status code
func (o *CreateServiceUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service unprocessable entity response has a 3xx status code
func (o *CreateServiceUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service unprocessable entity response has a 4xx status code
func (o *CreateServiceUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service unprocessable entity response has a 5xx status code
func (o *CreateServiceUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create service unprocessable entity response a status code equal to that given
func (o *CreateServiceUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create service unprocessable entity response
func (o *CreateServiceUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateServiceUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceUnprocessableEntity %s", 422, payload)
}

func (o *CreateServiceUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceUnprocessableEntity %s", 422, payload)
}

func (o *CreateServiceUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceTooManyRequests creates a CreateServiceTooManyRequests with default headers values
func NewCreateServiceTooManyRequests() *CreateServiceTooManyRequests {
	return &CreateServiceTooManyRequests{}
}

/*
CreateServiceTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateServiceTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create service too many requests response has a 2xx status code
func (o *CreateServiceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create service too many requests response has a 3xx status code
func (o *CreateServiceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create service too many requests response has a 4xx status code
func (o *CreateServiceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create service too many requests response has a 5xx status code
func (o *CreateServiceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create service too many requests response a status code equal to that given
func (o *CreateServiceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create service too many requests response
func (o *CreateServiceTooManyRequests) Code() int {
	return 429
}

func (o *CreateServiceTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceTooManyRequests %s", 429, payload)
}

func (o *CreateServiceTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /services][%d] createServiceTooManyRequests %s", 429, payload)
}

func (o *CreateServiceTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateServiceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
