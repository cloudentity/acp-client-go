// Code generated by go-swagger; DO NOT EDIT.

package tenants

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

// ListTenantsReader is a Reader for the ListTenants structure.
type ListTenantsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListTenantsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListTenantsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListTenantsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListTenantsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListTenantsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListTenantsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/system/tenants] listTenants", response, response.Code())
	}
}

// NewListTenantsOK creates a ListTenantsOK with default headers values
func NewListTenantsOK() *ListTenantsOK {
	return &ListTenantsOK{}
}

/*
ListTenantsOK describes a response with status code 200, with default header values.

List of tenants
*/
type ListTenantsOK struct {
	Payload *models.Tenants
}

// IsSuccess returns true when this list tenants o k response has a 2xx status code
func (o *ListTenantsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list tenants o k response has a 3xx status code
func (o *ListTenantsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list tenants o k response has a 4xx status code
func (o *ListTenantsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list tenants o k response has a 5xx status code
func (o *ListTenantsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list tenants o k response a status code equal to that given
func (o *ListTenantsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list tenants o k response
func (o *ListTenantsOK) Code() int {
	return 200
}

func (o *ListTenantsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsOK %s", 200, payload)
}

func (o *ListTenantsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsOK %s", 200, payload)
}

func (o *ListTenantsOK) GetPayload() *models.Tenants {
	return o.Payload
}

func (o *ListTenantsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Tenants)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListTenantsUnauthorized creates a ListTenantsUnauthorized with default headers values
func NewListTenantsUnauthorized() *ListTenantsUnauthorized {
	return &ListTenantsUnauthorized{}
}

/*
ListTenantsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListTenantsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list tenants unauthorized response has a 2xx status code
func (o *ListTenantsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list tenants unauthorized response has a 3xx status code
func (o *ListTenantsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list tenants unauthorized response has a 4xx status code
func (o *ListTenantsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list tenants unauthorized response has a 5xx status code
func (o *ListTenantsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list tenants unauthorized response a status code equal to that given
func (o *ListTenantsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list tenants unauthorized response
func (o *ListTenantsUnauthorized) Code() int {
	return 401
}

func (o *ListTenantsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsUnauthorized %s", 401, payload)
}

func (o *ListTenantsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsUnauthorized %s", 401, payload)
}

func (o *ListTenantsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListTenantsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListTenantsForbidden creates a ListTenantsForbidden with default headers values
func NewListTenantsForbidden() *ListTenantsForbidden {
	return &ListTenantsForbidden{}
}

/*
ListTenantsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListTenantsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list tenants forbidden response has a 2xx status code
func (o *ListTenantsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list tenants forbidden response has a 3xx status code
func (o *ListTenantsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list tenants forbidden response has a 4xx status code
func (o *ListTenantsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list tenants forbidden response has a 5xx status code
func (o *ListTenantsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list tenants forbidden response a status code equal to that given
func (o *ListTenantsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list tenants forbidden response
func (o *ListTenantsForbidden) Code() int {
	return 403
}

func (o *ListTenantsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsForbidden %s", 403, payload)
}

func (o *ListTenantsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsForbidden %s", 403, payload)
}

func (o *ListTenantsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListTenantsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListTenantsNotFound creates a ListTenantsNotFound with default headers values
func NewListTenantsNotFound() *ListTenantsNotFound {
	return &ListTenantsNotFound{}
}

/*
ListTenantsNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListTenantsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list tenants not found response has a 2xx status code
func (o *ListTenantsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list tenants not found response has a 3xx status code
func (o *ListTenantsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list tenants not found response has a 4xx status code
func (o *ListTenantsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list tenants not found response has a 5xx status code
func (o *ListTenantsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list tenants not found response a status code equal to that given
func (o *ListTenantsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list tenants not found response
func (o *ListTenantsNotFound) Code() int {
	return 404
}

func (o *ListTenantsNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsNotFound %s", 404, payload)
}

func (o *ListTenantsNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsNotFound %s", 404, payload)
}

func (o *ListTenantsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListTenantsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListTenantsTooManyRequests creates a ListTenantsTooManyRequests with default headers values
func NewListTenantsTooManyRequests() *ListTenantsTooManyRequests {
	return &ListTenantsTooManyRequests{}
}

/*
ListTenantsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListTenantsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list tenants too many requests response has a 2xx status code
func (o *ListTenantsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list tenants too many requests response has a 3xx status code
func (o *ListTenantsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list tenants too many requests response has a 4xx status code
func (o *ListTenantsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list tenants too many requests response has a 5xx status code
func (o *ListTenantsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list tenants too many requests response a status code equal to that given
func (o *ListTenantsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list tenants too many requests response
func (o *ListTenantsTooManyRequests) Code() int {
	return 429
}

func (o *ListTenantsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsTooManyRequests %s", 429, payload)
}

func (o *ListTenantsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants][%d] listTenantsTooManyRequests %s", 429, payload)
}

func (o *ListTenantsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListTenantsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
