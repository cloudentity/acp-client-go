// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// UpdateAzureB2CIDPReader is a Reader for the UpdateAzureB2CIDP structure.
type UpdateAzureB2CIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAzureB2CIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAzureB2CIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAzureB2CIDPBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAzureB2CIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateAzureB2CIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAzureB2CIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateAzureB2CIDPUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateAzureB2CIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /servers/{wid}/idps/azureb2c/{iid}] updateAzureB2CIDP", response, response.Code())
	}
}

// NewUpdateAzureB2CIDPOK creates a UpdateAzureB2CIDPOK with default headers values
func NewUpdateAzureB2CIDPOK() *UpdateAzureB2CIDPOK {
	return &UpdateAzureB2CIDPOK{}
}

/*
UpdateAzureB2CIDPOK describes a response with status code 200, with default header values.

AzureB2CIDP
*/
type UpdateAzureB2CIDPOK struct {
	Payload *models.AzureB2CIDP
}

// IsSuccess returns true when this update azure b2 c Id p o k response has a 2xx status code
func (o *UpdateAzureB2CIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update azure b2 c Id p o k response has a 3xx status code
func (o *UpdateAzureB2CIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p o k response has a 4xx status code
func (o *UpdateAzureB2CIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update azure b2 c Id p o k response has a 5xx status code
func (o *UpdateAzureB2CIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p o k response a status code equal to that given
func (o *UpdateAzureB2CIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update azure b2 c Id p o k response
func (o *UpdateAzureB2CIDPOK) Code() int {
	return 200
}

func (o *UpdateAzureB2CIDPOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPOK %s", 200, payload)
}

func (o *UpdateAzureB2CIDPOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPOK %s", 200, payload)
}

func (o *UpdateAzureB2CIDPOK) GetPayload() *models.AzureB2CIDP {
	return o.Payload
}

func (o *UpdateAzureB2CIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AzureB2CIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPBadRequest creates a UpdateAzureB2CIDPBadRequest with default headers values
func NewUpdateAzureB2CIDPBadRequest() *UpdateAzureB2CIDPBadRequest {
	return &UpdateAzureB2CIDPBadRequest{}
}

/*
UpdateAzureB2CIDPBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateAzureB2CIDPBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p bad request response has a 2xx status code
func (o *UpdateAzureB2CIDPBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p bad request response has a 3xx status code
func (o *UpdateAzureB2CIDPBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p bad request response has a 4xx status code
func (o *UpdateAzureB2CIDPBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p bad request response has a 5xx status code
func (o *UpdateAzureB2CIDPBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p bad request response a status code equal to that given
func (o *UpdateAzureB2CIDPBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update azure b2 c Id p bad request response
func (o *UpdateAzureB2CIDPBadRequest) Code() int {
	return 400
}

func (o *UpdateAzureB2CIDPBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPBadRequest %s", 400, payload)
}

func (o *UpdateAzureB2CIDPBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPBadRequest %s", 400, payload)
}

func (o *UpdateAzureB2CIDPBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPUnauthorized creates a UpdateAzureB2CIDPUnauthorized with default headers values
func NewUpdateAzureB2CIDPUnauthorized() *UpdateAzureB2CIDPUnauthorized {
	return &UpdateAzureB2CIDPUnauthorized{}
}

/*
UpdateAzureB2CIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateAzureB2CIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p unauthorized response has a 2xx status code
func (o *UpdateAzureB2CIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p unauthorized response has a 3xx status code
func (o *UpdateAzureB2CIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p unauthorized response has a 4xx status code
func (o *UpdateAzureB2CIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p unauthorized response has a 5xx status code
func (o *UpdateAzureB2CIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p unauthorized response a status code equal to that given
func (o *UpdateAzureB2CIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update azure b2 c Id p unauthorized response
func (o *UpdateAzureB2CIDPUnauthorized) Code() int {
	return 401
}

func (o *UpdateAzureB2CIDPUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPUnauthorized %s", 401, payload)
}

func (o *UpdateAzureB2CIDPUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPUnauthorized %s", 401, payload)
}

func (o *UpdateAzureB2CIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPForbidden creates a UpdateAzureB2CIDPForbidden with default headers values
func NewUpdateAzureB2CIDPForbidden() *UpdateAzureB2CIDPForbidden {
	return &UpdateAzureB2CIDPForbidden{}
}

/*
UpdateAzureB2CIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateAzureB2CIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p forbidden response has a 2xx status code
func (o *UpdateAzureB2CIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p forbidden response has a 3xx status code
func (o *UpdateAzureB2CIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p forbidden response has a 4xx status code
func (o *UpdateAzureB2CIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p forbidden response has a 5xx status code
func (o *UpdateAzureB2CIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p forbidden response a status code equal to that given
func (o *UpdateAzureB2CIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update azure b2 c Id p forbidden response
func (o *UpdateAzureB2CIDPForbidden) Code() int {
	return 403
}

func (o *UpdateAzureB2CIDPForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPForbidden %s", 403, payload)
}

func (o *UpdateAzureB2CIDPForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPForbidden %s", 403, payload)
}

func (o *UpdateAzureB2CIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPNotFound creates a UpdateAzureB2CIDPNotFound with default headers values
func NewUpdateAzureB2CIDPNotFound() *UpdateAzureB2CIDPNotFound {
	return &UpdateAzureB2CIDPNotFound{}
}

/*
UpdateAzureB2CIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateAzureB2CIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p not found response has a 2xx status code
func (o *UpdateAzureB2CIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p not found response has a 3xx status code
func (o *UpdateAzureB2CIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p not found response has a 4xx status code
func (o *UpdateAzureB2CIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p not found response has a 5xx status code
func (o *UpdateAzureB2CIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p not found response a status code equal to that given
func (o *UpdateAzureB2CIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update azure b2 c Id p not found response
func (o *UpdateAzureB2CIDPNotFound) Code() int {
	return 404
}

func (o *UpdateAzureB2CIDPNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPNotFound %s", 404, payload)
}

func (o *UpdateAzureB2CIDPNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPNotFound %s", 404, payload)
}

func (o *UpdateAzureB2CIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPUnprocessableEntity creates a UpdateAzureB2CIDPUnprocessableEntity with default headers values
func NewUpdateAzureB2CIDPUnprocessableEntity() *UpdateAzureB2CIDPUnprocessableEntity {
	return &UpdateAzureB2CIDPUnprocessableEntity{}
}

/*
UpdateAzureB2CIDPUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateAzureB2CIDPUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p unprocessable entity response has a 2xx status code
func (o *UpdateAzureB2CIDPUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p unprocessable entity response has a 3xx status code
func (o *UpdateAzureB2CIDPUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p unprocessable entity response has a 4xx status code
func (o *UpdateAzureB2CIDPUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p unprocessable entity response has a 5xx status code
func (o *UpdateAzureB2CIDPUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p unprocessable entity response a status code equal to that given
func (o *UpdateAzureB2CIDPUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update azure b2 c Id p unprocessable entity response
func (o *UpdateAzureB2CIDPUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateAzureB2CIDPUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateAzureB2CIDPUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPUnprocessableEntity %s", 422, payload)
}

func (o *UpdateAzureB2CIDPUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAzureB2CIDPTooManyRequests creates a UpdateAzureB2CIDPTooManyRequests with default headers values
func NewUpdateAzureB2CIDPTooManyRequests() *UpdateAzureB2CIDPTooManyRequests {
	return &UpdateAzureB2CIDPTooManyRequests{}
}

/*
UpdateAzureB2CIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateAzureB2CIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update azure b2 c Id p too many requests response has a 2xx status code
func (o *UpdateAzureB2CIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update azure b2 c Id p too many requests response has a 3xx status code
func (o *UpdateAzureB2CIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update azure b2 c Id p too many requests response has a 4xx status code
func (o *UpdateAzureB2CIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update azure b2 c Id p too many requests response has a 5xx status code
func (o *UpdateAzureB2CIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update azure b2 c Id p too many requests response a status code equal to that given
func (o *UpdateAzureB2CIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update azure b2 c Id p too many requests response
func (o *UpdateAzureB2CIDPTooManyRequests) Code() int {
	return 429
}

func (o *UpdateAzureB2CIDPTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateAzureB2CIDPTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /servers/{wid}/idps/azureb2c/{iid}][%d] updateAzureB2CIdPTooManyRequests %s", 429, payload)
}

func (o *UpdateAzureB2CIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAzureB2CIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
