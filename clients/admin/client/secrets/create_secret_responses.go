// Code generated by go-swagger; DO NOT EDIT.

package secrets

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

// CreateSecretReader is a Reader for the CreateSecret structure.
type CreateSecretReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateSecretReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateSecretCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateSecretBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateSecretUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateSecretForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateSecretNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateSecretConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateSecretUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateSecretTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/secrets] createSecret", response, response.Code())
	}
}

// NewCreateSecretCreated creates a CreateSecretCreated with default headers values
func NewCreateSecretCreated() *CreateSecretCreated {
	return &CreateSecretCreated{}
}

/*
CreateSecretCreated describes a response with status code 201, with default header values.

Secret
*/
type CreateSecretCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Secret
}

// IsSuccess returns true when this create secret created response has a 2xx status code
func (o *CreateSecretCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create secret created response has a 3xx status code
func (o *CreateSecretCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret created response has a 4xx status code
func (o *CreateSecretCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create secret created response has a 5xx status code
func (o *CreateSecretCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret created response a status code equal to that given
func (o *CreateSecretCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create secret created response
func (o *CreateSecretCreated) Code() int {
	return 201
}

func (o *CreateSecretCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretCreated %s", 201, payload)
}

func (o *CreateSecretCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretCreated %s", 201, payload)
}

func (o *CreateSecretCreated) GetPayload() *models.Secret {
	return o.Payload
}

func (o *CreateSecretCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Secret)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretBadRequest creates a CreateSecretBadRequest with default headers values
func NewCreateSecretBadRequest() *CreateSecretBadRequest {
	return &CreateSecretBadRequest{}
}

/*
CreateSecretBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateSecretBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret bad request response has a 2xx status code
func (o *CreateSecretBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret bad request response has a 3xx status code
func (o *CreateSecretBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret bad request response has a 4xx status code
func (o *CreateSecretBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret bad request response has a 5xx status code
func (o *CreateSecretBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret bad request response a status code equal to that given
func (o *CreateSecretBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create secret bad request response
func (o *CreateSecretBadRequest) Code() int {
	return 400
}

func (o *CreateSecretBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretBadRequest %s", 400, payload)
}

func (o *CreateSecretBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretBadRequest %s", 400, payload)
}

func (o *CreateSecretBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretUnauthorized creates a CreateSecretUnauthorized with default headers values
func NewCreateSecretUnauthorized() *CreateSecretUnauthorized {
	return &CreateSecretUnauthorized{}
}

/*
CreateSecretUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateSecretUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret unauthorized response has a 2xx status code
func (o *CreateSecretUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret unauthorized response has a 3xx status code
func (o *CreateSecretUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret unauthorized response has a 4xx status code
func (o *CreateSecretUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret unauthorized response has a 5xx status code
func (o *CreateSecretUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret unauthorized response a status code equal to that given
func (o *CreateSecretUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create secret unauthorized response
func (o *CreateSecretUnauthorized) Code() int {
	return 401
}

func (o *CreateSecretUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretUnauthorized %s", 401, payload)
}

func (o *CreateSecretUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretUnauthorized %s", 401, payload)
}

func (o *CreateSecretUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretForbidden creates a CreateSecretForbidden with default headers values
func NewCreateSecretForbidden() *CreateSecretForbidden {
	return &CreateSecretForbidden{}
}

/*
CreateSecretForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateSecretForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret forbidden response has a 2xx status code
func (o *CreateSecretForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret forbidden response has a 3xx status code
func (o *CreateSecretForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret forbidden response has a 4xx status code
func (o *CreateSecretForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret forbidden response has a 5xx status code
func (o *CreateSecretForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret forbidden response a status code equal to that given
func (o *CreateSecretForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create secret forbidden response
func (o *CreateSecretForbidden) Code() int {
	return 403
}

func (o *CreateSecretForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretForbidden %s", 403, payload)
}

func (o *CreateSecretForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretForbidden %s", 403, payload)
}

func (o *CreateSecretForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretNotFound creates a CreateSecretNotFound with default headers values
func NewCreateSecretNotFound() *CreateSecretNotFound {
	return &CreateSecretNotFound{}
}

/*
CreateSecretNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateSecretNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret not found response has a 2xx status code
func (o *CreateSecretNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret not found response has a 3xx status code
func (o *CreateSecretNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret not found response has a 4xx status code
func (o *CreateSecretNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret not found response has a 5xx status code
func (o *CreateSecretNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret not found response a status code equal to that given
func (o *CreateSecretNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create secret not found response
func (o *CreateSecretNotFound) Code() int {
	return 404
}

func (o *CreateSecretNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretNotFound %s", 404, payload)
}

func (o *CreateSecretNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretNotFound %s", 404, payload)
}

func (o *CreateSecretNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretConflict creates a CreateSecretConflict with default headers values
func NewCreateSecretConflict() *CreateSecretConflict {
	return &CreateSecretConflict{}
}

/*
CreateSecretConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreateSecretConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret conflict response has a 2xx status code
func (o *CreateSecretConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret conflict response has a 3xx status code
func (o *CreateSecretConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret conflict response has a 4xx status code
func (o *CreateSecretConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret conflict response has a 5xx status code
func (o *CreateSecretConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret conflict response a status code equal to that given
func (o *CreateSecretConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the create secret conflict response
func (o *CreateSecretConflict) Code() int {
	return 409
}

func (o *CreateSecretConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretConflict %s", 409, payload)
}

func (o *CreateSecretConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretConflict %s", 409, payload)
}

func (o *CreateSecretConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretUnprocessableEntity creates a CreateSecretUnprocessableEntity with default headers values
func NewCreateSecretUnprocessableEntity() *CreateSecretUnprocessableEntity {
	return &CreateSecretUnprocessableEntity{}
}

/*
CreateSecretUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateSecretUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret unprocessable entity response has a 2xx status code
func (o *CreateSecretUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret unprocessable entity response has a 3xx status code
func (o *CreateSecretUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret unprocessable entity response has a 4xx status code
func (o *CreateSecretUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret unprocessable entity response has a 5xx status code
func (o *CreateSecretUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret unprocessable entity response a status code equal to that given
func (o *CreateSecretUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create secret unprocessable entity response
func (o *CreateSecretUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateSecretUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretUnprocessableEntity %s", 422, payload)
}

func (o *CreateSecretUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretUnprocessableEntity %s", 422, payload)
}

func (o *CreateSecretUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSecretTooManyRequests creates a CreateSecretTooManyRequests with default headers values
func NewCreateSecretTooManyRequests() *CreateSecretTooManyRequests {
	return &CreateSecretTooManyRequests{}
}

/*
CreateSecretTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateSecretTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create secret too many requests response has a 2xx status code
func (o *CreateSecretTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create secret too many requests response has a 3xx status code
func (o *CreateSecretTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create secret too many requests response has a 4xx status code
func (o *CreateSecretTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create secret too many requests response has a 5xx status code
func (o *CreateSecretTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create secret too many requests response a status code equal to that given
func (o *CreateSecretTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create secret too many requests response
func (o *CreateSecretTooManyRequests) Code() int {
	return 429
}

func (o *CreateSecretTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretTooManyRequests %s", 429, payload)
}

func (o *CreateSecretTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/secrets][%d] createSecretTooManyRequests %s", 429, payload)
}

func (o *CreateSecretTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateSecretTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
