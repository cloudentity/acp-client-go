// Code generated by go-swagger; DO NOT EDIT.

package apis

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

// CreateAPIReader is a Reader for the CreateAPI structure.
type CreateAPIReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAPIReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateAPICreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateAPIBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateAPIUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateAPIForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateAPINotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateAPIUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateAPITooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /apis] createAPI", response, response.Code())
	}
}

// NewCreateAPICreated creates a CreateAPICreated with default headers values
func NewCreateAPICreated() *CreateAPICreated {
	return &CreateAPICreated{}
}

/*
CreateAPICreated describes a response with status code 201, with default header values.

API
*/
type CreateAPICreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.API
}

// IsSuccess returns true when this create Api created response has a 2xx status code
func (o *CreateAPICreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create Api created response has a 3xx status code
func (o *CreateAPICreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api created response has a 4xx status code
func (o *CreateAPICreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create Api created response has a 5xx status code
func (o *CreateAPICreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api created response a status code equal to that given
func (o *CreateAPICreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create Api created response
func (o *CreateAPICreated) Code() int {
	return 201
}

func (o *CreateAPICreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiCreated %s", 201, payload)
}

func (o *CreateAPICreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiCreated %s", 201, payload)
}

func (o *CreateAPICreated) GetPayload() *models.API {
	return o.Payload
}

func (o *CreateAPICreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.API)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPIBadRequest creates a CreateAPIBadRequest with default headers values
func NewCreateAPIBadRequest() *CreateAPIBadRequest {
	return &CreateAPIBadRequest{}
}

/*
CreateAPIBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateAPIBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api bad request response has a 2xx status code
func (o *CreateAPIBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api bad request response has a 3xx status code
func (o *CreateAPIBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api bad request response has a 4xx status code
func (o *CreateAPIBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api bad request response has a 5xx status code
func (o *CreateAPIBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api bad request response a status code equal to that given
func (o *CreateAPIBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create Api bad request response
func (o *CreateAPIBadRequest) Code() int {
	return 400
}

func (o *CreateAPIBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiBadRequest %s", 400, payload)
}

func (o *CreateAPIBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiBadRequest %s", 400, payload)
}

func (o *CreateAPIBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPIBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPIUnauthorized creates a CreateAPIUnauthorized with default headers values
func NewCreateAPIUnauthorized() *CreateAPIUnauthorized {
	return &CreateAPIUnauthorized{}
}

/*
CreateAPIUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateAPIUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api unauthorized response has a 2xx status code
func (o *CreateAPIUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api unauthorized response has a 3xx status code
func (o *CreateAPIUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api unauthorized response has a 4xx status code
func (o *CreateAPIUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api unauthorized response has a 5xx status code
func (o *CreateAPIUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api unauthorized response a status code equal to that given
func (o *CreateAPIUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create Api unauthorized response
func (o *CreateAPIUnauthorized) Code() int {
	return 401
}

func (o *CreateAPIUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiUnauthorized %s", 401, payload)
}

func (o *CreateAPIUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiUnauthorized %s", 401, payload)
}

func (o *CreateAPIUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPIUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPIForbidden creates a CreateAPIForbidden with default headers values
func NewCreateAPIForbidden() *CreateAPIForbidden {
	return &CreateAPIForbidden{}
}

/*
CreateAPIForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateAPIForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api forbidden response has a 2xx status code
func (o *CreateAPIForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api forbidden response has a 3xx status code
func (o *CreateAPIForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api forbidden response has a 4xx status code
func (o *CreateAPIForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api forbidden response has a 5xx status code
func (o *CreateAPIForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api forbidden response a status code equal to that given
func (o *CreateAPIForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create Api forbidden response
func (o *CreateAPIForbidden) Code() int {
	return 403
}

func (o *CreateAPIForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiForbidden %s", 403, payload)
}

func (o *CreateAPIForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiForbidden %s", 403, payload)
}

func (o *CreateAPIForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPIForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPINotFound creates a CreateAPINotFound with default headers values
func NewCreateAPINotFound() *CreateAPINotFound {
	return &CreateAPINotFound{}
}

/*
CreateAPINotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateAPINotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api not found response has a 2xx status code
func (o *CreateAPINotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api not found response has a 3xx status code
func (o *CreateAPINotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api not found response has a 4xx status code
func (o *CreateAPINotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api not found response has a 5xx status code
func (o *CreateAPINotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api not found response a status code equal to that given
func (o *CreateAPINotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create Api not found response
func (o *CreateAPINotFound) Code() int {
	return 404
}

func (o *CreateAPINotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiNotFound %s", 404, payload)
}

func (o *CreateAPINotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiNotFound %s", 404, payload)
}

func (o *CreateAPINotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPINotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPIUnprocessableEntity creates a CreateAPIUnprocessableEntity with default headers values
func NewCreateAPIUnprocessableEntity() *CreateAPIUnprocessableEntity {
	return &CreateAPIUnprocessableEntity{}
}

/*
CreateAPIUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateAPIUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api unprocessable entity response has a 2xx status code
func (o *CreateAPIUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api unprocessable entity response has a 3xx status code
func (o *CreateAPIUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api unprocessable entity response has a 4xx status code
func (o *CreateAPIUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api unprocessable entity response has a 5xx status code
func (o *CreateAPIUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api unprocessable entity response a status code equal to that given
func (o *CreateAPIUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create Api unprocessable entity response
func (o *CreateAPIUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateAPIUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiUnprocessableEntity %s", 422, payload)
}

func (o *CreateAPIUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiUnprocessableEntity %s", 422, payload)
}

func (o *CreateAPIUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPIUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateAPITooManyRequests creates a CreateAPITooManyRequests with default headers values
func NewCreateAPITooManyRequests() *CreateAPITooManyRequests {
	return &CreateAPITooManyRequests{}
}

/*
CreateAPITooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateAPITooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create Api too many requests response has a 2xx status code
func (o *CreateAPITooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create Api too many requests response has a 3xx status code
func (o *CreateAPITooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api too many requests response has a 4xx status code
func (o *CreateAPITooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create Api too many requests response has a 5xx status code
func (o *CreateAPITooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api too many requests response a status code equal to that given
func (o *CreateAPITooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create Api too many requests response
func (o *CreateAPITooManyRequests) Code() int {
	return 429
}

func (o *CreateAPITooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiTooManyRequests %s", 429, payload)
}

func (o *CreateAPITooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /apis][%d] createApiTooManyRequests %s", 429, payload)
}

func (o *CreateAPITooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateAPITooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
