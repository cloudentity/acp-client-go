// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/ksa/models"
)

// GetKSAConsentSystemReader is a Reader for the GetKSAConsentSystem structure.
type GetKSAConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetKSAConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetKSAConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetKSAConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetKSAConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetKSAConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetKSAConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetKSAConsentSystemOK creates a GetKSAConsentSystemOK with default headers values
func NewGetKSAConsentSystemOK() *GetKSAConsentSystemOK {
	return &GetKSAConsentSystemOK{}
}

/*
GetKSAConsentSystemOK describes a response with status code 200, with default header values.

GetKSAConsentResponse
*/
type GetKSAConsentSystemOK struct {
	Payload *models.GetKSAConsentResponse
}

// IsSuccess returns true when this get k s a consent system o k response has a 2xx status code
func (o *GetKSAConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get k s a consent system o k response has a 3xx status code
func (o *GetKSAConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get k s a consent system o k response has a 4xx status code
func (o *GetKSAConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get k s a consent system o k response has a 5xx status code
func (o *GetKSAConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get k s a consent system o k response a status code equal to that given
func (o *GetKSAConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get k s a consent system o k response
func (o *GetKSAConsentSystemOK) Code() int {
	return 200
}

func (o *GetKSAConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetKSAConsentSystemOK) String() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetKSAConsentSystemOK) GetPayload() *models.GetKSAConsentResponse {
	return o.Payload
}

func (o *GetKSAConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetKSAConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetKSAConsentSystemUnauthorized creates a GetKSAConsentSystemUnauthorized with default headers values
func NewGetKSAConsentSystemUnauthorized() *GetKSAConsentSystemUnauthorized {
	return &GetKSAConsentSystemUnauthorized{}
}

/*
GetKSAConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetKSAConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get k s a consent system unauthorized response has a 2xx status code
func (o *GetKSAConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get k s a consent system unauthorized response has a 3xx status code
func (o *GetKSAConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get k s a consent system unauthorized response has a 4xx status code
func (o *GetKSAConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get k s a consent system unauthorized response has a 5xx status code
func (o *GetKSAConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get k s a consent system unauthorized response a status code equal to that given
func (o *GetKSAConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get k s a consent system unauthorized response
func (o *GetKSAConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *GetKSAConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetKSAConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetKSAConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetKSAConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetKSAConsentSystemForbidden creates a GetKSAConsentSystemForbidden with default headers values
func NewGetKSAConsentSystemForbidden() *GetKSAConsentSystemForbidden {
	return &GetKSAConsentSystemForbidden{}
}

/*
GetKSAConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetKSAConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get k s a consent system forbidden response has a 2xx status code
func (o *GetKSAConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get k s a consent system forbidden response has a 3xx status code
func (o *GetKSAConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get k s a consent system forbidden response has a 4xx status code
func (o *GetKSAConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get k s a consent system forbidden response has a 5xx status code
func (o *GetKSAConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get k s a consent system forbidden response a status code equal to that given
func (o *GetKSAConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get k s a consent system forbidden response
func (o *GetKSAConsentSystemForbidden) Code() int {
	return 403
}

func (o *GetKSAConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetKSAConsentSystemForbidden) String() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetKSAConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetKSAConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetKSAConsentSystemNotFound creates a GetKSAConsentSystemNotFound with default headers values
func NewGetKSAConsentSystemNotFound() *GetKSAConsentSystemNotFound {
	return &GetKSAConsentSystemNotFound{}
}

/*
GetKSAConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetKSAConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get k s a consent system not found response has a 2xx status code
func (o *GetKSAConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get k s a consent system not found response has a 3xx status code
func (o *GetKSAConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get k s a consent system not found response has a 4xx status code
func (o *GetKSAConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get k s a consent system not found response has a 5xx status code
func (o *GetKSAConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get k s a consent system not found response a status code equal to that given
func (o *GetKSAConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get k s a consent system not found response
func (o *GetKSAConsentSystemNotFound) Code() int {
	return 404
}

func (o *GetKSAConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetKSAConsentSystemNotFound) String() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetKSAConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetKSAConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetKSAConsentSystemTooManyRequests creates a GetKSAConsentSystemTooManyRequests with default headers values
func NewGetKSAConsentSystemTooManyRequests() *GetKSAConsentSystemTooManyRequests {
	return &GetKSAConsentSystemTooManyRequests{}
}

/*
GetKSAConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetKSAConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get k s a consent system too many requests response has a 2xx status code
func (o *GetKSAConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get k s a consent system too many requests response has a 3xx status code
func (o *GetKSAConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get k s a consent system too many requests response has a 4xx status code
func (o *GetKSAConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get k s a consent system too many requests response has a 5xx status code
func (o *GetKSAConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get k s a consent system too many requests response a status code equal to that given
func (o *GetKSAConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get k s a consent system too many requests response
func (o *GetKSAConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *GetKSAConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetKSAConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /ksa/consent/{login}][%d] getKSAConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetKSAConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetKSAConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}