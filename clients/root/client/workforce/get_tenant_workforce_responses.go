// Code generated by go-swagger; DO NOT EDIT.

package workforce

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

// GetTenantWorkforceReader is a Reader for the GetTenantWorkforce structure.
type GetTenantWorkforceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTenantWorkforceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTenantWorkforceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetTenantWorkforceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetTenantWorkforceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetTenantWorkforceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetTenantWorkforceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/admin/tenants/{tid}/workforce] getTenantWorkforce", response, response.Code())
	}
}

// NewGetTenantWorkforceOK creates a GetTenantWorkforceOK with default headers values
func NewGetTenantWorkforceOK() *GetTenantWorkforceOK {
	return &GetTenantWorkforceOK{}
}

/*
GetTenantWorkforceOK describes a response with status code 200, with default header values.

Get tenant workforce settings
*/
type GetTenantWorkforceOK struct {
	Payload *models.WorkforceSettings
}

// IsSuccess returns true when this get tenant workforce o k response has a 2xx status code
func (o *GetTenantWorkforceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get tenant workforce o k response has a 3xx status code
func (o *GetTenantWorkforceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get tenant workforce o k response has a 4xx status code
func (o *GetTenantWorkforceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get tenant workforce o k response has a 5xx status code
func (o *GetTenantWorkforceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get tenant workforce o k response a status code equal to that given
func (o *GetTenantWorkforceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get tenant workforce o k response
func (o *GetTenantWorkforceOK) Code() int {
	return 200
}

func (o *GetTenantWorkforceOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceOK %s", 200, payload)
}

func (o *GetTenantWorkforceOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceOK %s", 200, payload)
}

func (o *GetTenantWorkforceOK) GetPayload() *models.WorkforceSettings {
	return o.Payload
}

func (o *GetTenantWorkforceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.WorkforceSettings)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTenantWorkforceUnauthorized creates a GetTenantWorkforceUnauthorized with default headers values
func NewGetTenantWorkforceUnauthorized() *GetTenantWorkforceUnauthorized {
	return &GetTenantWorkforceUnauthorized{}
}

/*
GetTenantWorkforceUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetTenantWorkforceUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get tenant workforce unauthorized response has a 2xx status code
func (o *GetTenantWorkforceUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get tenant workforce unauthorized response has a 3xx status code
func (o *GetTenantWorkforceUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get tenant workforce unauthorized response has a 4xx status code
func (o *GetTenantWorkforceUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get tenant workforce unauthorized response has a 5xx status code
func (o *GetTenantWorkforceUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get tenant workforce unauthorized response a status code equal to that given
func (o *GetTenantWorkforceUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get tenant workforce unauthorized response
func (o *GetTenantWorkforceUnauthorized) Code() int {
	return 401
}

func (o *GetTenantWorkforceUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceUnauthorized %s", 401, payload)
}

func (o *GetTenantWorkforceUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceUnauthorized %s", 401, payload)
}

func (o *GetTenantWorkforceUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTenantWorkforceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTenantWorkforceForbidden creates a GetTenantWorkforceForbidden with default headers values
func NewGetTenantWorkforceForbidden() *GetTenantWorkforceForbidden {
	return &GetTenantWorkforceForbidden{}
}

/*
GetTenantWorkforceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetTenantWorkforceForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get tenant workforce forbidden response has a 2xx status code
func (o *GetTenantWorkforceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get tenant workforce forbidden response has a 3xx status code
func (o *GetTenantWorkforceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get tenant workforce forbidden response has a 4xx status code
func (o *GetTenantWorkforceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get tenant workforce forbidden response has a 5xx status code
func (o *GetTenantWorkforceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get tenant workforce forbidden response a status code equal to that given
func (o *GetTenantWorkforceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get tenant workforce forbidden response
func (o *GetTenantWorkforceForbidden) Code() int {
	return 403
}

func (o *GetTenantWorkforceForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceForbidden %s", 403, payload)
}

func (o *GetTenantWorkforceForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceForbidden %s", 403, payload)
}

func (o *GetTenantWorkforceForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTenantWorkforceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTenantWorkforceNotFound creates a GetTenantWorkforceNotFound with default headers values
func NewGetTenantWorkforceNotFound() *GetTenantWorkforceNotFound {
	return &GetTenantWorkforceNotFound{}
}

/*
GetTenantWorkforceNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetTenantWorkforceNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get tenant workforce not found response has a 2xx status code
func (o *GetTenantWorkforceNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get tenant workforce not found response has a 3xx status code
func (o *GetTenantWorkforceNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get tenant workforce not found response has a 4xx status code
func (o *GetTenantWorkforceNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get tenant workforce not found response has a 5xx status code
func (o *GetTenantWorkforceNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get tenant workforce not found response a status code equal to that given
func (o *GetTenantWorkforceNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get tenant workforce not found response
func (o *GetTenantWorkforceNotFound) Code() int {
	return 404
}

func (o *GetTenantWorkforceNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceNotFound %s", 404, payload)
}

func (o *GetTenantWorkforceNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceNotFound %s", 404, payload)
}

func (o *GetTenantWorkforceNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTenantWorkforceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTenantWorkforceTooManyRequests creates a GetTenantWorkforceTooManyRequests with default headers values
func NewGetTenantWorkforceTooManyRequests() *GetTenantWorkforceTooManyRequests {
	return &GetTenantWorkforceTooManyRequests{}
}

/*
GetTenantWorkforceTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetTenantWorkforceTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get tenant workforce too many requests response has a 2xx status code
func (o *GetTenantWorkforceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get tenant workforce too many requests response has a 3xx status code
func (o *GetTenantWorkforceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get tenant workforce too many requests response has a 4xx status code
func (o *GetTenantWorkforceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get tenant workforce too many requests response has a 5xx status code
func (o *GetTenantWorkforceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get tenant workforce too many requests response a status code equal to that given
func (o *GetTenantWorkforceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get tenant workforce too many requests response
func (o *GetTenantWorkforceTooManyRequests) Code() int {
	return 429
}

func (o *GetTenantWorkforceTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceTooManyRequests %s", 429, payload)
}

func (o *GetTenantWorkforceTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tid}/workforce][%d] getTenantWorkforceTooManyRequests %s", 429, payload)
}

func (o *GetTenantWorkforceTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetTenantWorkforceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
