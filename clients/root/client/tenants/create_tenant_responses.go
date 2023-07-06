// Code generated by go-swagger; DO NOT EDIT.

package tenants

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// CreateTenantReader is a Reader for the CreateTenant structure.
type CreateTenantReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateTenantReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateTenantCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateTenantBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateTenantUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateTenantForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateTenantConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateTenantUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateTenantTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/system/tenants] createTenant", response, response.Code())
	}
}

// NewCreateTenantCreated creates a CreateTenantCreated with default headers values
func NewCreateTenantCreated() *CreateTenantCreated {
	return &CreateTenantCreated{}
}

/*
CreateTenantCreated describes a response with status code 201, with default header values.

Tenant created
*/
type CreateTenantCreated struct {
	Payload *models.TenantCreated
}

// IsSuccess returns true when this create tenant created response has a 2xx status code
func (o *CreateTenantCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create tenant created response has a 3xx status code
func (o *CreateTenantCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant created response has a 4xx status code
func (o *CreateTenantCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create tenant created response has a 5xx status code
func (o *CreateTenantCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant created response a status code equal to that given
func (o *CreateTenantCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create tenant created response
func (o *CreateTenantCreated) Code() int {
	return 201
}

func (o *CreateTenantCreated) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantCreated  %+v", 201, o.Payload)
}

func (o *CreateTenantCreated) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantCreated  %+v", 201, o.Payload)
}

func (o *CreateTenantCreated) GetPayload() *models.TenantCreated {
	return o.Payload
}

func (o *CreateTenantCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TenantCreated)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantBadRequest creates a CreateTenantBadRequest with default headers values
func NewCreateTenantBadRequest() *CreateTenantBadRequest {
	return &CreateTenantBadRequest{}
}

/*
CreateTenantBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateTenantBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant bad request response has a 2xx status code
func (o *CreateTenantBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant bad request response has a 3xx status code
func (o *CreateTenantBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant bad request response has a 4xx status code
func (o *CreateTenantBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant bad request response has a 5xx status code
func (o *CreateTenantBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant bad request response a status code equal to that given
func (o *CreateTenantBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create tenant bad request response
func (o *CreateTenantBadRequest) Code() int {
	return 400
}

func (o *CreateTenantBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantBadRequest  %+v", 400, o.Payload)
}

func (o *CreateTenantBadRequest) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantBadRequest  %+v", 400, o.Payload)
}

func (o *CreateTenantBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantUnauthorized creates a CreateTenantUnauthorized with default headers values
func NewCreateTenantUnauthorized() *CreateTenantUnauthorized {
	return &CreateTenantUnauthorized{}
}

/*
CreateTenantUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateTenantUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant unauthorized response has a 2xx status code
func (o *CreateTenantUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant unauthorized response has a 3xx status code
func (o *CreateTenantUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant unauthorized response has a 4xx status code
func (o *CreateTenantUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant unauthorized response has a 5xx status code
func (o *CreateTenantUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant unauthorized response a status code equal to that given
func (o *CreateTenantUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create tenant unauthorized response
func (o *CreateTenantUnauthorized) Code() int {
	return 401
}

func (o *CreateTenantUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateTenantUnauthorized) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateTenantUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantForbidden creates a CreateTenantForbidden with default headers values
func NewCreateTenantForbidden() *CreateTenantForbidden {
	return &CreateTenantForbidden{}
}

/*
CreateTenantForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateTenantForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant forbidden response has a 2xx status code
func (o *CreateTenantForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant forbidden response has a 3xx status code
func (o *CreateTenantForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant forbidden response has a 4xx status code
func (o *CreateTenantForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant forbidden response has a 5xx status code
func (o *CreateTenantForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant forbidden response a status code equal to that given
func (o *CreateTenantForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create tenant forbidden response
func (o *CreateTenantForbidden) Code() int {
	return 403
}

func (o *CreateTenantForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantForbidden  %+v", 403, o.Payload)
}

func (o *CreateTenantForbidden) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantForbidden  %+v", 403, o.Payload)
}

func (o *CreateTenantForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantConflict creates a CreateTenantConflict with default headers values
func NewCreateTenantConflict() *CreateTenantConflict {
	return &CreateTenantConflict{}
}

/*
CreateTenantConflict describes a response with status code 409, with default header values.

Conflict
*/
type CreateTenantConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant conflict response has a 2xx status code
func (o *CreateTenantConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant conflict response has a 3xx status code
func (o *CreateTenantConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant conflict response has a 4xx status code
func (o *CreateTenantConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant conflict response has a 5xx status code
func (o *CreateTenantConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant conflict response a status code equal to that given
func (o *CreateTenantConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the create tenant conflict response
func (o *CreateTenantConflict) Code() int {
	return 409
}

func (o *CreateTenantConflict) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantConflict  %+v", 409, o.Payload)
}

func (o *CreateTenantConflict) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantConflict  %+v", 409, o.Payload)
}

func (o *CreateTenantConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantUnprocessableEntity creates a CreateTenantUnprocessableEntity with default headers values
func NewCreateTenantUnprocessableEntity() *CreateTenantUnprocessableEntity {
	return &CreateTenantUnprocessableEntity{}
}

/*
CreateTenantUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CreateTenantUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant unprocessable entity response has a 2xx status code
func (o *CreateTenantUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant unprocessable entity response has a 3xx status code
func (o *CreateTenantUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant unprocessable entity response has a 4xx status code
func (o *CreateTenantUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant unprocessable entity response has a 5xx status code
func (o *CreateTenantUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant unprocessable entity response a status code equal to that given
func (o *CreateTenantUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create tenant unprocessable entity response
func (o *CreateTenantUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateTenantUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateTenantUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateTenantUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateTenantTooManyRequests creates a CreateTenantTooManyRequests with default headers values
func NewCreateTenantTooManyRequests() *CreateTenantTooManyRequests {
	return &CreateTenantTooManyRequests{}
}

/*
CreateTenantTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type CreateTenantTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this create tenant too many requests response has a 2xx status code
func (o *CreateTenantTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create tenant too many requests response has a 3xx status code
func (o *CreateTenantTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create tenant too many requests response has a 4xx status code
func (o *CreateTenantTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create tenant too many requests response has a 5xx status code
func (o *CreateTenantTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create tenant too many requests response a status code equal to that given
func (o *CreateTenantTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create tenant too many requests response
func (o *CreateTenantTooManyRequests) Code() int {
	return 429
}

func (o *CreateTenantTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateTenantTooManyRequests) String() string {
	return fmt.Sprintf("[POST /api/system/tenants][%d] createTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateTenantTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateTenantTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
