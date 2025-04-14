// Code generated by go-swagger; DO NOT EDIT.

package licenses

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

// GetConfiguredLicensesReader is a Reader for the GetConfiguredLicenses structure.
type GetConfiguredLicensesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetConfiguredLicensesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetConfiguredLicensesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetConfiguredLicensesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetConfiguredLicensesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetConfiguredLicensesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetConfiguredLicensesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/admin/tenants/{tenantID}/licenses] getConfiguredLicenses", response, response.Code())
	}
}

// NewGetConfiguredLicensesOK creates a GetConfiguredLicensesOK with default headers values
func NewGetConfiguredLicensesOK() *GetConfiguredLicensesOK {
	return &GetConfiguredLicensesOK{}
}

/*
GetConfiguredLicensesOK describes a response with status code 200, with default header values.

Licenses
*/
type GetConfiguredLicensesOK struct {
	Payload *models.Licenses
}

// IsSuccess returns true when this get configured licenses o k response has a 2xx status code
func (o *GetConfiguredLicensesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get configured licenses o k response has a 3xx status code
func (o *GetConfiguredLicensesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get configured licenses o k response has a 4xx status code
func (o *GetConfiguredLicensesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get configured licenses o k response has a 5xx status code
func (o *GetConfiguredLicensesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get configured licenses o k response a status code equal to that given
func (o *GetConfiguredLicensesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get configured licenses o k response
func (o *GetConfiguredLicensesOK) Code() int {
	return 200
}

func (o *GetConfiguredLicensesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesOK %s", 200, payload)
}

func (o *GetConfiguredLicensesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesOK %s", 200, payload)
}

func (o *GetConfiguredLicensesOK) GetPayload() *models.Licenses {
	return o.Payload
}

func (o *GetConfiguredLicensesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Licenses)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetConfiguredLicensesUnauthorized creates a GetConfiguredLicensesUnauthorized with default headers values
func NewGetConfiguredLicensesUnauthorized() *GetConfiguredLicensesUnauthorized {
	return &GetConfiguredLicensesUnauthorized{}
}

/*
GetConfiguredLicensesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetConfiguredLicensesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get configured licenses unauthorized response has a 2xx status code
func (o *GetConfiguredLicensesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get configured licenses unauthorized response has a 3xx status code
func (o *GetConfiguredLicensesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get configured licenses unauthorized response has a 4xx status code
func (o *GetConfiguredLicensesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get configured licenses unauthorized response has a 5xx status code
func (o *GetConfiguredLicensesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get configured licenses unauthorized response a status code equal to that given
func (o *GetConfiguredLicensesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get configured licenses unauthorized response
func (o *GetConfiguredLicensesUnauthorized) Code() int {
	return 401
}

func (o *GetConfiguredLicensesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesUnauthorized %s", 401, payload)
}

func (o *GetConfiguredLicensesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesUnauthorized %s", 401, payload)
}

func (o *GetConfiguredLicensesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetConfiguredLicensesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetConfiguredLicensesForbidden creates a GetConfiguredLicensesForbidden with default headers values
func NewGetConfiguredLicensesForbidden() *GetConfiguredLicensesForbidden {
	return &GetConfiguredLicensesForbidden{}
}

/*
GetConfiguredLicensesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetConfiguredLicensesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get configured licenses forbidden response has a 2xx status code
func (o *GetConfiguredLicensesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get configured licenses forbidden response has a 3xx status code
func (o *GetConfiguredLicensesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get configured licenses forbidden response has a 4xx status code
func (o *GetConfiguredLicensesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get configured licenses forbidden response has a 5xx status code
func (o *GetConfiguredLicensesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get configured licenses forbidden response a status code equal to that given
func (o *GetConfiguredLicensesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get configured licenses forbidden response
func (o *GetConfiguredLicensesForbidden) Code() int {
	return 403
}

func (o *GetConfiguredLicensesForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesForbidden %s", 403, payload)
}

func (o *GetConfiguredLicensesForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesForbidden %s", 403, payload)
}

func (o *GetConfiguredLicensesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetConfiguredLicensesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetConfiguredLicensesNotFound creates a GetConfiguredLicensesNotFound with default headers values
func NewGetConfiguredLicensesNotFound() *GetConfiguredLicensesNotFound {
	return &GetConfiguredLicensesNotFound{}
}

/*
GetConfiguredLicensesNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetConfiguredLicensesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get configured licenses not found response has a 2xx status code
func (o *GetConfiguredLicensesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get configured licenses not found response has a 3xx status code
func (o *GetConfiguredLicensesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get configured licenses not found response has a 4xx status code
func (o *GetConfiguredLicensesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get configured licenses not found response has a 5xx status code
func (o *GetConfiguredLicensesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get configured licenses not found response a status code equal to that given
func (o *GetConfiguredLicensesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get configured licenses not found response
func (o *GetConfiguredLicensesNotFound) Code() int {
	return 404
}

func (o *GetConfiguredLicensesNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesNotFound %s", 404, payload)
}

func (o *GetConfiguredLicensesNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesNotFound %s", 404, payload)
}

func (o *GetConfiguredLicensesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetConfiguredLicensesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetConfiguredLicensesTooManyRequests creates a GetConfiguredLicensesTooManyRequests with default headers values
func NewGetConfiguredLicensesTooManyRequests() *GetConfiguredLicensesTooManyRequests {
	return &GetConfiguredLicensesTooManyRequests{}
}

/*
GetConfiguredLicensesTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetConfiguredLicensesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get configured licenses too many requests response has a 2xx status code
func (o *GetConfiguredLicensesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get configured licenses too many requests response has a 3xx status code
func (o *GetConfiguredLicensesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get configured licenses too many requests response has a 4xx status code
func (o *GetConfiguredLicensesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get configured licenses too many requests response has a 5xx status code
func (o *GetConfiguredLicensesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get configured licenses too many requests response a status code equal to that given
func (o *GetConfiguredLicensesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get configured licenses too many requests response
func (o *GetConfiguredLicensesTooManyRequests) Code() int {
	return 429
}

func (o *GetConfiguredLicensesTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesTooManyRequests %s", 429, payload)
}

func (o *GetConfiguredLicensesTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/licenses][%d] getConfiguredLicensesTooManyRequests %s", 429, payload)
}

func (o *GetConfiguredLicensesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetConfiguredLicensesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
