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

// GetAdminTenantReader is a Reader for the GetAdminTenant structure.
type GetAdminTenantReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAdminTenantReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAdminTenantOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAdminTenantUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAdminTenantForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAdminTenantNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAdminTenantTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAdminTenantOK creates a GetAdminTenantOK with default headers values
func NewGetAdminTenantOK() *GetAdminTenantOK {
	return &GetAdminTenantOK{}
}

/*
GetAdminTenantOK describes a response with status code 200, with default header values.

Tenant
*/
type GetAdminTenantOK struct {
	Payload *models.Tenant
}

// IsSuccess returns true when this get admin tenant o k response has a 2xx status code
func (o *GetAdminTenantOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get admin tenant o k response has a 3xx status code
func (o *GetAdminTenantOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get admin tenant o k response has a 4xx status code
func (o *GetAdminTenantOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get admin tenant o k response has a 5xx status code
func (o *GetAdminTenantOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get admin tenant o k response a status code equal to that given
func (o *GetAdminTenantOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetAdminTenantOK) Error() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantOK  %+v", 200, o.Payload)
}

func (o *GetAdminTenantOK) String() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantOK  %+v", 200, o.Payload)
}

func (o *GetAdminTenantOK) GetPayload() *models.Tenant {
	return o.Payload
}

func (o *GetAdminTenantOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Tenant)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAdminTenantUnauthorized creates a GetAdminTenantUnauthorized with default headers values
func NewGetAdminTenantUnauthorized() *GetAdminTenantUnauthorized {
	return &GetAdminTenantUnauthorized{}
}

/*
GetAdminTenantUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetAdminTenantUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get admin tenant unauthorized response has a 2xx status code
func (o *GetAdminTenantUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get admin tenant unauthorized response has a 3xx status code
func (o *GetAdminTenantUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get admin tenant unauthorized response has a 4xx status code
func (o *GetAdminTenantUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get admin tenant unauthorized response has a 5xx status code
func (o *GetAdminTenantUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get admin tenant unauthorized response a status code equal to that given
func (o *GetAdminTenantUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetAdminTenantUnauthorized) Error() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAdminTenantUnauthorized) String() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAdminTenantUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAdminTenantUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAdminTenantForbidden creates a GetAdminTenantForbidden with default headers values
func NewGetAdminTenantForbidden() *GetAdminTenantForbidden {
	return &GetAdminTenantForbidden{}
}

/*
GetAdminTenantForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetAdminTenantForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get admin tenant forbidden response has a 2xx status code
func (o *GetAdminTenantForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get admin tenant forbidden response has a 3xx status code
func (o *GetAdminTenantForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get admin tenant forbidden response has a 4xx status code
func (o *GetAdminTenantForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get admin tenant forbidden response has a 5xx status code
func (o *GetAdminTenantForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get admin tenant forbidden response a status code equal to that given
func (o *GetAdminTenantForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetAdminTenantForbidden) Error() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantForbidden  %+v", 403, o.Payload)
}

func (o *GetAdminTenantForbidden) String() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantForbidden  %+v", 403, o.Payload)
}

func (o *GetAdminTenantForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAdminTenantForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAdminTenantNotFound creates a GetAdminTenantNotFound with default headers values
func NewGetAdminTenantNotFound() *GetAdminTenantNotFound {
	return &GetAdminTenantNotFound{}
}

/*
GetAdminTenantNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetAdminTenantNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get admin tenant not found response has a 2xx status code
func (o *GetAdminTenantNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get admin tenant not found response has a 3xx status code
func (o *GetAdminTenantNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get admin tenant not found response has a 4xx status code
func (o *GetAdminTenantNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get admin tenant not found response has a 5xx status code
func (o *GetAdminTenantNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get admin tenant not found response a status code equal to that given
func (o *GetAdminTenantNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetAdminTenantNotFound) Error() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantNotFound  %+v", 404, o.Payload)
}

func (o *GetAdminTenantNotFound) String() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantNotFound  %+v", 404, o.Payload)
}

func (o *GetAdminTenantNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAdminTenantNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAdminTenantTooManyRequests creates a GetAdminTenantTooManyRequests with default headers values
func NewGetAdminTenantTooManyRequests() *GetAdminTenantTooManyRequests {
	return &GetAdminTenantTooManyRequests{}
}

/*
GetAdminTenantTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetAdminTenantTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get admin tenant too many requests response has a 2xx status code
func (o *GetAdminTenantTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get admin tenant too many requests response has a 3xx status code
func (o *GetAdminTenantTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get admin tenant too many requests response has a 4xx status code
func (o *GetAdminTenantTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get admin tenant too many requests response has a 5xx status code
func (o *GetAdminTenantTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get admin tenant too many requests response a status code equal to that given
func (o *GetAdminTenantTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetAdminTenantTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAdminTenantTooManyRequests) String() string {
	return fmt.Sprintf("[GET /tenant][%d] getAdminTenantTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAdminTenantTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAdminTenantTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
