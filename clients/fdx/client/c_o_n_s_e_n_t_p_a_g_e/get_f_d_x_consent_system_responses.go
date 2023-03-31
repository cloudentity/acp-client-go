// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// GetFDXConsentSystemReader is a Reader for the GetFDXConsentSystem structure.
type GetFDXConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFDXConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFDXConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetFDXConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetFDXConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetFDXConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetFDXConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetFDXConsentSystemOK creates a GetFDXConsentSystemOK with default headers values
func NewGetFDXConsentSystemOK() *GetFDXConsentSystemOK {
	return &GetFDXConsentSystemOK{}
}

/*
GetFDXConsentSystemOK describes a response with status code 200, with default header values.

GetFDXConsentResponse
*/
type GetFDXConsentSystemOK struct {
	Payload *models.GetFDXConsentResponse
}

// IsSuccess returns true when this get f d x consent system o k response has a 2xx status code
func (o *GetFDXConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get f d x consent system o k response has a 3xx status code
func (o *GetFDXConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent system o k response has a 4xx status code
func (o *GetFDXConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get f d x consent system o k response has a 5xx status code
func (o *GetFDXConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent system o k response a status code equal to that given
func (o *GetFDXConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get f d x consent system o k response
func (o *GetFDXConsentSystemOK) Code() int {
	return 200
}

func (o *GetFDXConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetFDXConsentSystemOK) String() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetFDXConsentSystemOK) GetPayload() *models.GetFDXConsentResponse {
	return o.Payload
}

func (o *GetFDXConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetFDXConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentSystemUnauthorized creates a GetFDXConsentSystemUnauthorized with default headers values
func NewGetFDXConsentSystemUnauthorized() *GetFDXConsentSystemUnauthorized {
	return &GetFDXConsentSystemUnauthorized{}
}

/*
GetFDXConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetFDXConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get f d x consent system unauthorized response has a 2xx status code
func (o *GetFDXConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent system unauthorized response has a 3xx status code
func (o *GetFDXConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent system unauthorized response has a 4xx status code
func (o *GetFDXConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent system unauthorized response has a 5xx status code
func (o *GetFDXConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent system unauthorized response a status code equal to that given
func (o *GetFDXConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get f d x consent system unauthorized response
func (o *GetFDXConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *GetFDXConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetFDXConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetFDXConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFDXConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentSystemForbidden creates a GetFDXConsentSystemForbidden with default headers values
func NewGetFDXConsentSystemForbidden() *GetFDXConsentSystemForbidden {
	return &GetFDXConsentSystemForbidden{}
}

/*
GetFDXConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetFDXConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get f d x consent system forbidden response has a 2xx status code
func (o *GetFDXConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent system forbidden response has a 3xx status code
func (o *GetFDXConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent system forbidden response has a 4xx status code
func (o *GetFDXConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent system forbidden response has a 5xx status code
func (o *GetFDXConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent system forbidden response a status code equal to that given
func (o *GetFDXConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get f d x consent system forbidden response
func (o *GetFDXConsentSystemForbidden) Code() int {
	return 403
}

func (o *GetFDXConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetFDXConsentSystemForbidden) String() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetFDXConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFDXConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentSystemNotFound creates a GetFDXConsentSystemNotFound with default headers values
func NewGetFDXConsentSystemNotFound() *GetFDXConsentSystemNotFound {
	return &GetFDXConsentSystemNotFound{}
}

/*
GetFDXConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetFDXConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get f d x consent system not found response has a 2xx status code
func (o *GetFDXConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent system not found response has a 3xx status code
func (o *GetFDXConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent system not found response has a 4xx status code
func (o *GetFDXConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent system not found response has a 5xx status code
func (o *GetFDXConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent system not found response a status code equal to that given
func (o *GetFDXConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get f d x consent system not found response
func (o *GetFDXConsentSystemNotFound) Code() int {
	return 404
}

func (o *GetFDXConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetFDXConsentSystemNotFound) String() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetFDXConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFDXConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFDXConsentSystemTooManyRequests creates a GetFDXConsentSystemTooManyRequests with default headers values
func NewGetFDXConsentSystemTooManyRequests() *GetFDXConsentSystemTooManyRequests {
	return &GetFDXConsentSystemTooManyRequests{}
}

/*
GetFDXConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetFDXConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get f d x consent system too many requests response has a 2xx status code
func (o *GetFDXConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get f d x consent system too many requests response has a 3xx status code
func (o *GetFDXConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get f d x consent system too many requests response has a 4xx status code
func (o *GetFDXConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get f d x consent system too many requests response has a 5xx status code
func (o *GetFDXConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get f d x consent system too many requests response a status code equal to that given
func (o *GetFDXConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get f d x consent system too many requests response
func (o *GetFDXConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *GetFDXConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetFDXConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /fdx/fdx/{login}][%d] getFDXConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetFDXConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFDXConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
