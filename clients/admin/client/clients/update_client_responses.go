// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// UpdateClientReader is a Reader for the UpdateClient structure.
type UpdateClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateClientUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /clients/{cid}] updateClient", response, response.Code())
	}
}

// NewUpdateClientOK creates a UpdateClientOK with default headers values
func NewUpdateClientOK() *UpdateClientOK {
	return &UpdateClientOK{}
}

/*
UpdateClientOK describes a response with status code 200, with default header values.

Client
*/
type UpdateClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this update client o k response has a 2xx status code
func (o *UpdateClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update client o k response has a 3xx status code
func (o *UpdateClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client o k response has a 4xx status code
func (o *UpdateClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update client o k response has a 5xx status code
func (o *UpdateClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update client o k response a status code equal to that given
func (o *UpdateClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update client o k response
func (o *UpdateClientOK) Code() int {
	return 200
}

func (o *UpdateClientOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientOK %s", 200, payload)
}

func (o *UpdateClientOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientOK %s", 200, payload)
}

func (o *UpdateClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *UpdateClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ClientAdminResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientBadRequest creates a UpdateClientBadRequest with default headers values
func NewUpdateClientBadRequest() *UpdateClientBadRequest {
	return &UpdateClientBadRequest{}
}

/*
UpdateClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client bad request response has a 2xx status code
func (o *UpdateClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client bad request response has a 3xx status code
func (o *UpdateClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client bad request response has a 4xx status code
func (o *UpdateClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client bad request response has a 5xx status code
func (o *UpdateClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update client bad request response a status code equal to that given
func (o *UpdateClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update client bad request response
func (o *UpdateClientBadRequest) Code() int {
	return 400
}

func (o *UpdateClientBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientBadRequest %s", 400, payload)
}

func (o *UpdateClientBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientBadRequest %s", 400, payload)
}

func (o *UpdateClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientUnauthorized creates a UpdateClientUnauthorized with default headers values
func NewUpdateClientUnauthorized() *UpdateClientUnauthorized {
	return &UpdateClientUnauthorized{}
}

/*
UpdateClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client unauthorized response has a 2xx status code
func (o *UpdateClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client unauthorized response has a 3xx status code
func (o *UpdateClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client unauthorized response has a 4xx status code
func (o *UpdateClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client unauthorized response has a 5xx status code
func (o *UpdateClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update client unauthorized response a status code equal to that given
func (o *UpdateClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update client unauthorized response
func (o *UpdateClientUnauthorized) Code() int {
	return 401
}

func (o *UpdateClientUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientUnauthorized %s", 401, payload)
}

func (o *UpdateClientUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientUnauthorized %s", 401, payload)
}

func (o *UpdateClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientForbidden creates a UpdateClientForbidden with default headers values
func NewUpdateClientForbidden() *UpdateClientForbidden {
	return &UpdateClientForbidden{}
}

/*
UpdateClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client forbidden response has a 2xx status code
func (o *UpdateClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client forbidden response has a 3xx status code
func (o *UpdateClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client forbidden response has a 4xx status code
func (o *UpdateClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client forbidden response has a 5xx status code
func (o *UpdateClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update client forbidden response a status code equal to that given
func (o *UpdateClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update client forbidden response
func (o *UpdateClientForbidden) Code() int {
	return 403
}

func (o *UpdateClientForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientForbidden %s", 403, payload)
}

func (o *UpdateClientForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientForbidden %s", 403, payload)
}

func (o *UpdateClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientNotFound creates a UpdateClientNotFound with default headers values
func NewUpdateClientNotFound() *UpdateClientNotFound {
	return &UpdateClientNotFound{}
}

/*
UpdateClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client not found response has a 2xx status code
func (o *UpdateClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client not found response has a 3xx status code
func (o *UpdateClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client not found response has a 4xx status code
func (o *UpdateClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client not found response has a 5xx status code
func (o *UpdateClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update client not found response a status code equal to that given
func (o *UpdateClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update client not found response
func (o *UpdateClientNotFound) Code() int {
	return 404
}

func (o *UpdateClientNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientNotFound %s", 404, payload)
}

func (o *UpdateClientNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientNotFound %s", 404, payload)
}

func (o *UpdateClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientUnprocessableEntity creates a UpdateClientUnprocessableEntity with default headers values
func NewUpdateClientUnprocessableEntity() *UpdateClientUnprocessableEntity {
	return &UpdateClientUnprocessableEntity{}
}

/*
UpdateClientUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateClientUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client unprocessable entity response has a 2xx status code
func (o *UpdateClientUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client unprocessable entity response has a 3xx status code
func (o *UpdateClientUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client unprocessable entity response has a 4xx status code
func (o *UpdateClientUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client unprocessable entity response has a 5xx status code
func (o *UpdateClientUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update client unprocessable entity response a status code equal to that given
func (o *UpdateClientUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update client unprocessable entity response
func (o *UpdateClientUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateClientUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientUnprocessableEntity %s", 422, payload)
}

func (o *UpdateClientUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientUnprocessableEntity %s", 422, payload)
}

func (o *UpdateClientUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateClientTooManyRequests creates a UpdateClientTooManyRequests with default headers values
func NewUpdateClientTooManyRequests() *UpdateClientTooManyRequests {
	return &UpdateClientTooManyRequests{}
}

/*
UpdateClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update client too many requests response has a 2xx status code
func (o *UpdateClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update client too many requests response has a 3xx status code
func (o *UpdateClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update client too many requests response has a 4xx status code
func (o *UpdateClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update client too many requests response has a 5xx status code
func (o *UpdateClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update client too many requests response a status code equal to that given
func (o *UpdateClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update client too many requests response
func (o *UpdateClientTooManyRequests) Code() int {
	return 429
}

func (o *UpdateClientTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientTooManyRequests %s", 429, payload)
}

func (o *UpdateClientTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /clients/{cid}][%d] updateClientTooManyRequests %s", 429, payload)
}

func (o *UpdateClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
