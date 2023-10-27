// Code generated by go-swagger; DO NOT EDIT.

package tenants

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UpdateAdminTenantReader is a Reader for the UpdateAdminTenant structure.
type UpdateAdminTenantReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateAdminTenantReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateAdminTenantOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateAdminTenantBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateAdminTenantUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateAdminTenantForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateAdminTenantNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateAdminTenantUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateAdminTenantTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /tenant] updateAdminTenant", response, response.Code())
	}
}

// NewUpdateAdminTenantOK creates a UpdateAdminTenantOK with default headers values
func NewUpdateAdminTenantOK() *UpdateAdminTenantOK {
	return &UpdateAdminTenantOK{}
}

/*
UpdateAdminTenantOK describes a response with status code 200, with default header values.

Tenant
*/
type UpdateAdminTenantOK struct {
	Payload *models.Tenant
}

// IsSuccess returns true when this update admin tenant o k response has a 2xx status code
func (o *UpdateAdminTenantOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update admin tenant o k response has a 3xx status code
func (o *UpdateAdminTenantOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant o k response has a 4xx status code
func (o *UpdateAdminTenantOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update admin tenant o k response has a 5xx status code
func (o *UpdateAdminTenantOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant o k response a status code equal to that given
func (o *UpdateAdminTenantOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update admin tenant o k response
func (o *UpdateAdminTenantOK) Code() int {
	return 200
}

func (o *UpdateAdminTenantOK) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantOK  %+v", 200, o.Payload)
}

func (o *UpdateAdminTenantOK) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantOK  %+v", 200, o.Payload)
}

func (o *UpdateAdminTenantOK) GetPayload() *models.Tenant {
	return o.Payload
}

func (o *UpdateAdminTenantOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Tenant)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantBadRequest creates a UpdateAdminTenantBadRequest with default headers values
func NewUpdateAdminTenantBadRequest() *UpdateAdminTenantBadRequest {
	return &UpdateAdminTenantBadRequest{}
}

/*
UpdateAdminTenantBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UpdateAdminTenantBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant bad request response has a 2xx status code
func (o *UpdateAdminTenantBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant bad request response has a 3xx status code
func (o *UpdateAdminTenantBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant bad request response has a 4xx status code
func (o *UpdateAdminTenantBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant bad request response has a 5xx status code
func (o *UpdateAdminTenantBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant bad request response a status code equal to that given
func (o *UpdateAdminTenantBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the update admin tenant bad request response
func (o *UpdateAdminTenantBadRequest) Code() int {
	return 400
}

func (o *UpdateAdminTenantBadRequest) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateAdminTenantBadRequest) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateAdminTenantBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantUnauthorized creates a UpdateAdminTenantUnauthorized with default headers values
func NewUpdateAdminTenantUnauthorized() *UpdateAdminTenantUnauthorized {
	return &UpdateAdminTenantUnauthorized{}
}

/*
UpdateAdminTenantUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateAdminTenantUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant unauthorized response has a 2xx status code
func (o *UpdateAdminTenantUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant unauthorized response has a 3xx status code
func (o *UpdateAdminTenantUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant unauthorized response has a 4xx status code
func (o *UpdateAdminTenantUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant unauthorized response has a 5xx status code
func (o *UpdateAdminTenantUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant unauthorized response a status code equal to that given
func (o *UpdateAdminTenantUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update admin tenant unauthorized response
func (o *UpdateAdminTenantUnauthorized) Code() int {
	return 401
}

func (o *UpdateAdminTenantUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateAdminTenantUnauthorized) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateAdminTenantUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantForbidden creates a UpdateAdminTenantForbidden with default headers values
func NewUpdateAdminTenantForbidden() *UpdateAdminTenantForbidden {
	return &UpdateAdminTenantForbidden{}
}

/*
UpdateAdminTenantForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateAdminTenantForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant forbidden response has a 2xx status code
func (o *UpdateAdminTenantForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant forbidden response has a 3xx status code
func (o *UpdateAdminTenantForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant forbidden response has a 4xx status code
func (o *UpdateAdminTenantForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant forbidden response has a 5xx status code
func (o *UpdateAdminTenantForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant forbidden response a status code equal to that given
func (o *UpdateAdminTenantForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update admin tenant forbidden response
func (o *UpdateAdminTenantForbidden) Code() int {
	return 403
}

func (o *UpdateAdminTenantForbidden) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantForbidden  %+v", 403, o.Payload)
}

func (o *UpdateAdminTenantForbidden) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantForbidden  %+v", 403, o.Payload)
}

func (o *UpdateAdminTenantForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantNotFound creates a UpdateAdminTenantNotFound with default headers values
func NewUpdateAdminTenantNotFound() *UpdateAdminTenantNotFound {
	return &UpdateAdminTenantNotFound{}
}

/*
UpdateAdminTenantNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateAdminTenantNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant not found response has a 2xx status code
func (o *UpdateAdminTenantNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant not found response has a 3xx status code
func (o *UpdateAdminTenantNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant not found response has a 4xx status code
func (o *UpdateAdminTenantNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant not found response has a 5xx status code
func (o *UpdateAdminTenantNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant not found response a status code equal to that given
func (o *UpdateAdminTenantNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update admin tenant not found response
func (o *UpdateAdminTenantNotFound) Code() int {
	return 404
}

func (o *UpdateAdminTenantNotFound) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantNotFound  %+v", 404, o.Payload)
}

func (o *UpdateAdminTenantNotFound) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantNotFound  %+v", 404, o.Payload)
}

func (o *UpdateAdminTenantNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantUnprocessableEntity creates a UpdateAdminTenantUnprocessableEntity with default headers values
func NewUpdateAdminTenantUnprocessableEntity() *UpdateAdminTenantUnprocessableEntity {
	return &UpdateAdminTenantUnprocessableEntity{}
}

/*
UpdateAdminTenantUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateAdminTenantUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant unprocessable entity response has a 2xx status code
func (o *UpdateAdminTenantUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant unprocessable entity response has a 3xx status code
func (o *UpdateAdminTenantUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant unprocessable entity response has a 4xx status code
func (o *UpdateAdminTenantUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant unprocessable entity response has a 5xx status code
func (o *UpdateAdminTenantUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant unprocessable entity response a status code equal to that given
func (o *UpdateAdminTenantUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update admin tenant unprocessable entity response
func (o *UpdateAdminTenantUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateAdminTenantUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateAdminTenantUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateAdminTenantUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateAdminTenantTooManyRequests creates a UpdateAdminTenantTooManyRequests with default headers values
func NewUpdateAdminTenantTooManyRequests() *UpdateAdminTenantTooManyRequests {
	return &UpdateAdminTenantTooManyRequests{}
}

/*
UpdateAdminTenantTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateAdminTenantTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update admin tenant too many requests response has a 2xx status code
func (o *UpdateAdminTenantTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update admin tenant too many requests response has a 3xx status code
func (o *UpdateAdminTenantTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update admin tenant too many requests response has a 4xx status code
func (o *UpdateAdminTenantTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update admin tenant too many requests response has a 5xx status code
func (o *UpdateAdminTenantTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update admin tenant too many requests response a status code equal to that given
func (o *UpdateAdminTenantTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update admin tenant too many requests response
func (o *UpdateAdminTenantTooManyRequests) Code() int {
	return 429
}

func (o *UpdateAdminTenantTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateAdminTenantTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /tenant][%d] updateAdminTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateAdminTenantTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateAdminTenantTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
