// Code generated by go-swagger; DO NOT EDIT.

package security

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// GetSecurityReader is a Reader for the GetSecurity structure.
type GetSecurityReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetSecurityReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetSecurityOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetSecurityUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetSecurityForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetSecurityNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetSecurityTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/admin/tenants/security] getSecurity", response, response.Code())
	}
}

// NewGetSecurityOK creates a GetSecurityOK with default headers values
func NewGetSecurityOK() *GetSecurityOK {
	return &GetSecurityOK{}
}

/*
GetSecurityOK describes a response with status code 200, with default header values.

Get security
*/
type GetSecurityOK struct {
	Payload *models.SecureOptions
}

// IsSuccess returns true when this get security o k response has a 2xx status code
func (o *GetSecurityOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get security o k response has a 3xx status code
func (o *GetSecurityOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get security o k response has a 4xx status code
func (o *GetSecurityOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get security o k response has a 5xx status code
func (o *GetSecurityOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get security o k response a status code equal to that given
func (o *GetSecurityOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get security o k response
func (o *GetSecurityOK) Code() int {
	return 200
}

func (o *GetSecurityOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityOK %s", 200, payload)
}

func (o *GetSecurityOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityOK %s", 200, payload)
}

func (o *GetSecurityOK) GetPayload() *models.SecureOptions {
	return o.Payload
}

func (o *GetSecurityOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SecureOptions)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSecurityUnauthorized creates a GetSecurityUnauthorized with default headers values
func NewGetSecurityUnauthorized() *GetSecurityUnauthorized {
	return &GetSecurityUnauthorized{}
}

/*
GetSecurityUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetSecurityUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get security unauthorized response has a 2xx status code
func (o *GetSecurityUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get security unauthorized response has a 3xx status code
func (o *GetSecurityUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get security unauthorized response has a 4xx status code
func (o *GetSecurityUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get security unauthorized response has a 5xx status code
func (o *GetSecurityUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get security unauthorized response a status code equal to that given
func (o *GetSecurityUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get security unauthorized response
func (o *GetSecurityUnauthorized) Code() int {
	return 401
}

func (o *GetSecurityUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityUnauthorized %s", 401, payload)
}

func (o *GetSecurityUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityUnauthorized %s", 401, payload)
}

func (o *GetSecurityUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSecurityUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSecurityForbidden creates a GetSecurityForbidden with default headers values
func NewGetSecurityForbidden() *GetSecurityForbidden {
	return &GetSecurityForbidden{}
}

/*
GetSecurityForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetSecurityForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get security forbidden response has a 2xx status code
func (o *GetSecurityForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get security forbidden response has a 3xx status code
func (o *GetSecurityForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get security forbidden response has a 4xx status code
func (o *GetSecurityForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get security forbidden response has a 5xx status code
func (o *GetSecurityForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get security forbidden response a status code equal to that given
func (o *GetSecurityForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get security forbidden response
func (o *GetSecurityForbidden) Code() int {
	return 403
}

func (o *GetSecurityForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityForbidden %s", 403, payload)
}

func (o *GetSecurityForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityForbidden %s", 403, payload)
}

func (o *GetSecurityForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSecurityForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSecurityNotFound creates a GetSecurityNotFound with default headers values
func NewGetSecurityNotFound() *GetSecurityNotFound {
	return &GetSecurityNotFound{}
}

/*
GetSecurityNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetSecurityNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get security not found response has a 2xx status code
func (o *GetSecurityNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get security not found response has a 3xx status code
func (o *GetSecurityNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get security not found response has a 4xx status code
func (o *GetSecurityNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get security not found response has a 5xx status code
func (o *GetSecurityNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get security not found response a status code equal to that given
func (o *GetSecurityNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get security not found response
func (o *GetSecurityNotFound) Code() int {
	return 404
}

func (o *GetSecurityNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityNotFound %s", 404, payload)
}

func (o *GetSecurityNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityNotFound %s", 404, payload)
}

func (o *GetSecurityNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSecurityNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSecurityTooManyRequests creates a GetSecurityTooManyRequests with default headers values
func NewGetSecurityTooManyRequests() *GetSecurityTooManyRequests {
	return &GetSecurityTooManyRequests{}
}

/*
GetSecurityTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetSecurityTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get security too many requests response has a 2xx status code
func (o *GetSecurityTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get security too many requests response has a 3xx status code
func (o *GetSecurityTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get security too many requests response has a 4xx status code
func (o *GetSecurityTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get security too many requests response has a 5xx status code
func (o *GetSecurityTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get security too many requests response a status code equal to that given
func (o *GetSecurityTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get security too many requests response
func (o *GetSecurityTooManyRequests) Code() int {
	return 429
}

func (o *GetSecurityTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityTooManyRequests %s", 429, payload)
}

func (o *GetSecurityTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/security][%d] getSecurityTooManyRequests %s", 429, payload)
}

func (o *GetSecurityTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSecurityTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
