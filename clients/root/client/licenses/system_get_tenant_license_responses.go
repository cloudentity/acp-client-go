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

// SystemGetTenantLicenseReader is a Reader for the SystemGetTenantLicense structure.
type SystemGetTenantLicenseReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemGetTenantLicenseReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemGetTenantLicenseOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemGetTenantLicenseUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemGetTenantLicenseForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemGetTenantLicenseNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemGetTenantLicenseTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/system/tenants/{tenantID}/license] systemGetTenantLicense", response, response.Code())
	}
}

// NewSystemGetTenantLicenseOK creates a SystemGetTenantLicenseOK with default headers values
func NewSystemGetTenantLicenseOK() *SystemGetTenantLicenseOK {
	return &SystemGetTenantLicenseOK{}
}

/*
SystemGetTenantLicenseOK describes a response with status code 200, with default header values.

License
*/
type SystemGetTenantLicenseOK struct {
	Payload *models.License
}

// IsSuccess returns true when this system get tenant license o k response has a 2xx status code
func (o *SystemGetTenantLicenseOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system get tenant license o k response has a 3xx status code
func (o *SystemGetTenantLicenseOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get tenant license o k response has a 4xx status code
func (o *SystemGetTenantLicenseOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system get tenant license o k response has a 5xx status code
func (o *SystemGetTenantLicenseOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system get tenant license o k response a status code equal to that given
func (o *SystemGetTenantLicenseOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the system get tenant license o k response
func (o *SystemGetTenantLicenseOK) Code() int {
	return 200
}

func (o *SystemGetTenantLicenseOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseOK %s", 200, payload)
}

func (o *SystemGetTenantLicenseOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseOK %s", 200, payload)
}

func (o *SystemGetTenantLicenseOK) GetPayload() *models.License {
	return o.Payload
}

func (o *SystemGetTenantLicenseOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.License)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetTenantLicenseUnauthorized creates a SystemGetTenantLicenseUnauthorized with default headers values
func NewSystemGetTenantLicenseUnauthorized() *SystemGetTenantLicenseUnauthorized {
	return &SystemGetTenantLicenseUnauthorized{}
}

/*
SystemGetTenantLicenseUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemGetTenantLicenseUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get tenant license unauthorized response has a 2xx status code
func (o *SystemGetTenantLicenseUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get tenant license unauthorized response has a 3xx status code
func (o *SystemGetTenantLicenseUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get tenant license unauthorized response has a 4xx status code
func (o *SystemGetTenantLicenseUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get tenant license unauthorized response has a 5xx status code
func (o *SystemGetTenantLicenseUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system get tenant license unauthorized response a status code equal to that given
func (o *SystemGetTenantLicenseUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system get tenant license unauthorized response
func (o *SystemGetTenantLicenseUnauthorized) Code() int {
	return 401
}

func (o *SystemGetTenantLicenseUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseUnauthorized %s", 401, payload)
}

func (o *SystemGetTenantLicenseUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseUnauthorized %s", 401, payload)
}

func (o *SystemGetTenantLicenseUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetTenantLicenseUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetTenantLicenseForbidden creates a SystemGetTenantLicenseForbidden with default headers values
func NewSystemGetTenantLicenseForbidden() *SystemGetTenantLicenseForbidden {
	return &SystemGetTenantLicenseForbidden{}
}

/*
SystemGetTenantLicenseForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemGetTenantLicenseForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get tenant license forbidden response has a 2xx status code
func (o *SystemGetTenantLicenseForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get tenant license forbidden response has a 3xx status code
func (o *SystemGetTenantLicenseForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get tenant license forbidden response has a 4xx status code
func (o *SystemGetTenantLicenseForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get tenant license forbidden response has a 5xx status code
func (o *SystemGetTenantLicenseForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system get tenant license forbidden response a status code equal to that given
func (o *SystemGetTenantLicenseForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system get tenant license forbidden response
func (o *SystemGetTenantLicenseForbidden) Code() int {
	return 403
}

func (o *SystemGetTenantLicenseForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseForbidden %s", 403, payload)
}

func (o *SystemGetTenantLicenseForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseForbidden %s", 403, payload)
}

func (o *SystemGetTenantLicenseForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetTenantLicenseForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetTenantLicenseNotFound creates a SystemGetTenantLicenseNotFound with default headers values
func NewSystemGetTenantLicenseNotFound() *SystemGetTenantLicenseNotFound {
	return &SystemGetTenantLicenseNotFound{}
}

/*
SystemGetTenantLicenseNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemGetTenantLicenseNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get tenant license not found response has a 2xx status code
func (o *SystemGetTenantLicenseNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get tenant license not found response has a 3xx status code
func (o *SystemGetTenantLicenseNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get tenant license not found response has a 4xx status code
func (o *SystemGetTenantLicenseNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get tenant license not found response has a 5xx status code
func (o *SystemGetTenantLicenseNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system get tenant license not found response a status code equal to that given
func (o *SystemGetTenantLicenseNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the system get tenant license not found response
func (o *SystemGetTenantLicenseNotFound) Code() int {
	return 404
}

func (o *SystemGetTenantLicenseNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseNotFound %s", 404, payload)
}

func (o *SystemGetTenantLicenseNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseNotFound %s", 404, payload)
}

func (o *SystemGetTenantLicenseNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetTenantLicenseNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetTenantLicenseTooManyRequests creates a SystemGetTenantLicenseTooManyRequests with default headers values
func NewSystemGetTenantLicenseTooManyRequests() *SystemGetTenantLicenseTooManyRequests {
	return &SystemGetTenantLicenseTooManyRequests{}
}

/*
SystemGetTenantLicenseTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemGetTenantLicenseTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get tenant license too many requests response has a 2xx status code
func (o *SystemGetTenantLicenseTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get tenant license too many requests response has a 3xx status code
func (o *SystemGetTenantLicenseTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get tenant license too many requests response has a 4xx status code
func (o *SystemGetTenantLicenseTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get tenant license too many requests response has a 5xx status code
func (o *SystemGetTenantLicenseTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system get tenant license too many requests response a status code equal to that given
func (o *SystemGetTenantLicenseTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system get tenant license too many requests response
func (o *SystemGetTenantLicenseTooManyRequests) Code() int {
	return 429
}

func (o *SystemGetTenantLicenseTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseTooManyRequests %s", 429, payload)
}

func (o *SystemGetTenantLicenseTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/system/tenants/{tenantID}/license][%d] systemGetTenantLicenseTooManyRequests %s", 429, payload)
}

func (o *SystemGetTenantLicenseTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetTenantLicenseTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
