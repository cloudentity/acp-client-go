// Code generated by go-swagger; DO NOT EDIT.

package policies

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

// UpdatePolicyReader is a Reader for the UpdatePolicy structure.
type UpdatePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewUpdatePolicyCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdatePolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdatePolicyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdatePolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdatePolicyConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdatePolicyUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdatePolicyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /policies/{pid}] updatePolicy", response, response.Code())
	}
}

// NewUpdatePolicyCreated creates a UpdatePolicyCreated with default headers values
func NewUpdatePolicyCreated() *UpdatePolicyCreated {
	return &UpdatePolicyCreated{}
}

/*
UpdatePolicyCreated describes a response with status code 201, with default header values.

Policy
*/
type UpdatePolicyCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Policy
}

// IsSuccess returns true when this update policy created response has a 2xx status code
func (o *UpdatePolicyCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update policy created response has a 3xx status code
func (o *UpdatePolicyCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy created response has a 4xx status code
func (o *UpdatePolicyCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this update policy created response has a 5xx status code
func (o *UpdatePolicyCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy created response a status code equal to that given
func (o *UpdatePolicyCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the update policy created response
func (o *UpdatePolicyCreated) Code() int {
	return 201
}

func (o *UpdatePolicyCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyCreated %s", 201, payload)
}

func (o *UpdatePolicyCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyCreated %s", 201, payload)
}

func (o *UpdatePolicyCreated) GetPayload() *models.Policy {
	return o.Payload
}

func (o *UpdatePolicyCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Policy)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyBadRequest creates a UpdatePolicyBadRequest with default headers values
func NewUpdatePolicyBadRequest() *UpdatePolicyBadRequest {
	return &UpdatePolicyBadRequest{}
}

/*
UpdatePolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdatePolicyBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy bad request response has a 2xx status code
func (o *UpdatePolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy bad request response has a 3xx status code
func (o *UpdatePolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy bad request response has a 4xx status code
func (o *UpdatePolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy bad request response has a 5xx status code
func (o *UpdatePolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy bad request response a status code equal to that given
func (o *UpdatePolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update policy bad request response
func (o *UpdatePolicyBadRequest) Code() int {
	return 400
}

func (o *UpdatePolicyBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyBadRequest %s", 400, payload)
}

func (o *UpdatePolicyBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyBadRequest %s", 400, payload)
}

func (o *UpdatePolicyBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyUnauthorized creates a UpdatePolicyUnauthorized with default headers values
func NewUpdatePolicyUnauthorized() *UpdatePolicyUnauthorized {
	return &UpdatePolicyUnauthorized{}
}

/*
UpdatePolicyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdatePolicyUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy unauthorized response has a 2xx status code
func (o *UpdatePolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy unauthorized response has a 3xx status code
func (o *UpdatePolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy unauthorized response has a 4xx status code
func (o *UpdatePolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy unauthorized response has a 5xx status code
func (o *UpdatePolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy unauthorized response a status code equal to that given
func (o *UpdatePolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update policy unauthorized response
func (o *UpdatePolicyUnauthorized) Code() int {
	return 401
}

func (o *UpdatePolicyUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyUnauthorized %s", 401, payload)
}

func (o *UpdatePolicyUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyUnauthorized %s", 401, payload)
}

func (o *UpdatePolicyUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyForbidden creates a UpdatePolicyForbidden with default headers values
func NewUpdatePolicyForbidden() *UpdatePolicyForbidden {
	return &UpdatePolicyForbidden{}
}

/*
UpdatePolicyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdatePolicyForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy forbidden response has a 2xx status code
func (o *UpdatePolicyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy forbidden response has a 3xx status code
func (o *UpdatePolicyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy forbidden response has a 4xx status code
func (o *UpdatePolicyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy forbidden response has a 5xx status code
func (o *UpdatePolicyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy forbidden response a status code equal to that given
func (o *UpdatePolicyForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update policy forbidden response
func (o *UpdatePolicyForbidden) Code() int {
	return 403
}

func (o *UpdatePolicyForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyForbidden %s", 403, payload)
}

func (o *UpdatePolicyForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyForbidden %s", 403, payload)
}

func (o *UpdatePolicyForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyNotFound creates a UpdatePolicyNotFound with default headers values
func NewUpdatePolicyNotFound() *UpdatePolicyNotFound {
	return &UpdatePolicyNotFound{}
}

/*
UpdatePolicyNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdatePolicyNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy not found response has a 2xx status code
func (o *UpdatePolicyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy not found response has a 3xx status code
func (o *UpdatePolicyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy not found response has a 4xx status code
func (o *UpdatePolicyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy not found response has a 5xx status code
func (o *UpdatePolicyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy not found response a status code equal to that given
func (o *UpdatePolicyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update policy not found response
func (o *UpdatePolicyNotFound) Code() int {
	return 404
}

func (o *UpdatePolicyNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyNotFound %s", 404, payload)
}

func (o *UpdatePolicyNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyNotFound %s", 404, payload)
}

func (o *UpdatePolicyNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyConflict creates a UpdatePolicyConflict with default headers values
func NewUpdatePolicyConflict() *UpdatePolicyConflict {
	return &UpdatePolicyConflict{}
}

/*
UpdatePolicyConflict describes a response with status code 409, with default header values.

Conflict
*/
type UpdatePolicyConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy conflict response has a 2xx status code
func (o *UpdatePolicyConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy conflict response has a 3xx status code
func (o *UpdatePolicyConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy conflict response has a 4xx status code
func (o *UpdatePolicyConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy conflict response has a 5xx status code
func (o *UpdatePolicyConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy conflict response a status code equal to that given
func (o *UpdatePolicyConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the update policy conflict response
func (o *UpdatePolicyConflict) Code() int {
	return 409
}

func (o *UpdatePolicyConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyConflict %s", 409, payload)
}

func (o *UpdatePolicyConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyConflict %s", 409, payload)
}

func (o *UpdatePolicyConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyUnprocessableEntity creates a UpdatePolicyUnprocessableEntity with default headers values
func NewUpdatePolicyUnprocessableEntity() *UpdatePolicyUnprocessableEntity {
	return &UpdatePolicyUnprocessableEntity{}
}

/*
UpdatePolicyUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdatePolicyUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy unprocessable entity response has a 2xx status code
func (o *UpdatePolicyUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy unprocessable entity response has a 3xx status code
func (o *UpdatePolicyUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy unprocessable entity response has a 4xx status code
func (o *UpdatePolicyUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy unprocessable entity response has a 5xx status code
func (o *UpdatePolicyUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy unprocessable entity response a status code equal to that given
func (o *UpdatePolicyUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update policy unprocessable entity response
func (o *UpdatePolicyUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdatePolicyUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyUnprocessableEntity %s", 422, payload)
}

func (o *UpdatePolicyUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyUnprocessableEntity %s", 422, payload)
}

func (o *UpdatePolicyUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePolicyTooManyRequests creates a UpdatePolicyTooManyRequests with default headers values
func NewUpdatePolicyTooManyRequests() *UpdatePolicyTooManyRequests {
	return &UpdatePolicyTooManyRequests{}
}

/*
UpdatePolicyTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdatePolicyTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update policy too many requests response has a 2xx status code
func (o *UpdatePolicyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update policy too many requests response has a 3xx status code
func (o *UpdatePolicyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update policy too many requests response has a 4xx status code
func (o *UpdatePolicyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update policy too many requests response has a 5xx status code
func (o *UpdatePolicyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update policy too many requests response a status code equal to that given
func (o *UpdatePolicyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update policy too many requests response
func (o *UpdatePolicyTooManyRequests) Code() int {
	return 429
}

func (o *UpdatePolicyTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyTooManyRequests %s", 429, payload)
}

func (o *UpdatePolicyTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /policies/{pid}][%d] updatePolicyTooManyRequests %s", 429, payload)
}

func (o *UpdatePolicyTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdatePolicyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
