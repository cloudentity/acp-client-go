// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemListPoolsReader is a Reader for the SystemListPools structure.
type SystemListPoolsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemListPoolsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemListPoolsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemListPoolsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemListPoolsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemListPoolsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /system/pools] systemListPools", response, response.Code())
	}
}

// NewSystemListPoolsOK creates a SystemListPoolsOK with default headers values
func NewSystemListPoolsOK() *SystemListPoolsOK {
	return &SystemListPoolsOK{}
}

/*
SystemListPoolsOK describes a response with status code 200, with default header values.

Pools
*/
type SystemListPoolsOK struct {
	Payload *models.Pools
}

// IsSuccess returns true when this system list pools o k response has a 2xx status code
func (o *SystemListPoolsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system list pools o k response has a 3xx status code
func (o *SystemListPoolsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list pools o k response has a 4xx status code
func (o *SystemListPoolsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system list pools o k response has a 5xx status code
func (o *SystemListPoolsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system list pools o k response a status code equal to that given
func (o *SystemListPoolsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the system list pools o k response
func (o *SystemListPoolsOK) Code() int {
	return 200
}

func (o *SystemListPoolsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsOK %s", 200, payload)
}

func (o *SystemListPoolsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsOK %s", 200, payload)
}

func (o *SystemListPoolsOK) GetPayload() *models.Pools {
	return o.Payload
}

func (o *SystemListPoolsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Pools)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListPoolsUnauthorized creates a SystemListPoolsUnauthorized with default headers values
func NewSystemListPoolsUnauthorized() *SystemListPoolsUnauthorized {
	return &SystemListPoolsUnauthorized{}
}

/*
SystemListPoolsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemListPoolsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list pools unauthorized response has a 2xx status code
func (o *SystemListPoolsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list pools unauthorized response has a 3xx status code
func (o *SystemListPoolsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list pools unauthorized response has a 4xx status code
func (o *SystemListPoolsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list pools unauthorized response has a 5xx status code
func (o *SystemListPoolsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system list pools unauthorized response a status code equal to that given
func (o *SystemListPoolsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system list pools unauthorized response
func (o *SystemListPoolsUnauthorized) Code() int {
	return 401
}

func (o *SystemListPoolsUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsUnauthorized %s", 401, payload)
}

func (o *SystemListPoolsUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsUnauthorized %s", 401, payload)
}

func (o *SystemListPoolsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListPoolsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListPoolsForbidden creates a SystemListPoolsForbidden with default headers values
func NewSystemListPoolsForbidden() *SystemListPoolsForbidden {
	return &SystemListPoolsForbidden{}
}

/*
SystemListPoolsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemListPoolsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list pools forbidden response has a 2xx status code
func (o *SystemListPoolsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list pools forbidden response has a 3xx status code
func (o *SystemListPoolsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list pools forbidden response has a 4xx status code
func (o *SystemListPoolsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list pools forbidden response has a 5xx status code
func (o *SystemListPoolsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system list pools forbidden response a status code equal to that given
func (o *SystemListPoolsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system list pools forbidden response
func (o *SystemListPoolsForbidden) Code() int {
	return 403
}

func (o *SystemListPoolsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsForbidden %s", 403, payload)
}

func (o *SystemListPoolsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsForbidden %s", 403, payload)
}

func (o *SystemListPoolsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListPoolsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemListPoolsTooManyRequests creates a SystemListPoolsTooManyRequests with default headers values
func NewSystemListPoolsTooManyRequests() *SystemListPoolsTooManyRequests {
	return &SystemListPoolsTooManyRequests{}
}

/*
SystemListPoolsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemListPoolsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system list pools too many requests response has a 2xx status code
func (o *SystemListPoolsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system list pools too many requests response has a 3xx status code
func (o *SystemListPoolsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system list pools too many requests response has a 4xx status code
func (o *SystemListPoolsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system list pools too many requests response has a 5xx status code
func (o *SystemListPoolsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system list pools too many requests response a status code equal to that given
func (o *SystemListPoolsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system list pools too many requests response
func (o *SystemListPoolsTooManyRequests) Code() int {
	return 429
}

func (o *SystemListPoolsTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsTooManyRequests %s", 429, payload)
}

func (o *SystemListPoolsTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /system/pools][%d] systemListPoolsTooManyRequests %s", 429, payload)
}

func (o *SystemListPoolsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemListPoolsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
