// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// GetFilePaymentConsentSystemReader is a Reader for the GetFilePaymentConsentSystem structure.
type GetFilePaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFilePaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFilePaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetFilePaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetFilePaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetFilePaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetFilePaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/file-payment-consent/{login}] getFilePaymentConsentSystem", response, response.Code())
	}
}

// NewGetFilePaymentConsentSystemOK creates a GetFilePaymentConsentSystemOK with default headers values
func NewGetFilePaymentConsentSystemOK() *GetFilePaymentConsentSystemOK {
	return &GetFilePaymentConsentSystemOK{}
}

/*
GetFilePaymentConsentSystemOK describes a response with status code 200, with default header values.

GetFilePaymentConsentResponse
*/
type GetFilePaymentConsentSystemOK struct {
	Payload *models.GetFilePaymentConsentResponse
}

// IsSuccess returns true when this get file payment consent system o k response has a 2xx status code
func (o *GetFilePaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get file payment consent system o k response has a 3xx status code
func (o *GetFilePaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent system o k response has a 4xx status code
func (o *GetFilePaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file payment consent system o k response has a 5xx status code
func (o *GetFilePaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent system o k response a status code equal to that given
func (o *GetFilePaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get file payment consent system o k response
func (o *GetFilePaymentConsentSystemOK) Code() int {
	return 200
}

func (o *GetFilePaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetFilePaymentConsentSystemOK) String() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetFilePaymentConsentSystemOK) GetPayload() *models.GetFilePaymentConsentResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetFilePaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentSystemUnauthorized creates a GetFilePaymentConsentSystemUnauthorized with default headers values
func NewGetFilePaymentConsentSystemUnauthorized() *GetFilePaymentConsentSystemUnauthorized {
	return &GetFilePaymentConsentSystemUnauthorized{}
}

/*
GetFilePaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetFilePaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get file payment consent system unauthorized response has a 2xx status code
func (o *GetFilePaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent system unauthorized response has a 3xx status code
func (o *GetFilePaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent system unauthorized response has a 4xx status code
func (o *GetFilePaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent system unauthorized response has a 5xx status code
func (o *GetFilePaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent system unauthorized response a status code equal to that given
func (o *GetFilePaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get file payment consent system unauthorized response
func (o *GetFilePaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *GetFilePaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetFilePaymentConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetFilePaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFilePaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentSystemForbidden creates a GetFilePaymentConsentSystemForbidden with default headers values
func NewGetFilePaymentConsentSystemForbidden() *GetFilePaymentConsentSystemForbidden {
	return &GetFilePaymentConsentSystemForbidden{}
}

/*
GetFilePaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetFilePaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get file payment consent system forbidden response has a 2xx status code
func (o *GetFilePaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent system forbidden response has a 3xx status code
func (o *GetFilePaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent system forbidden response has a 4xx status code
func (o *GetFilePaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent system forbidden response has a 5xx status code
func (o *GetFilePaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent system forbidden response a status code equal to that given
func (o *GetFilePaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get file payment consent system forbidden response
func (o *GetFilePaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *GetFilePaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetFilePaymentConsentSystemForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetFilePaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFilePaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentSystemNotFound creates a GetFilePaymentConsentSystemNotFound with default headers values
func NewGetFilePaymentConsentSystemNotFound() *GetFilePaymentConsentSystemNotFound {
	return &GetFilePaymentConsentSystemNotFound{}
}

/*
GetFilePaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetFilePaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get file payment consent system not found response has a 2xx status code
func (o *GetFilePaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent system not found response has a 3xx status code
func (o *GetFilePaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent system not found response has a 4xx status code
func (o *GetFilePaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent system not found response has a 5xx status code
func (o *GetFilePaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent system not found response a status code equal to that given
func (o *GetFilePaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get file payment consent system not found response
func (o *GetFilePaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *GetFilePaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetFilePaymentConsentSystemNotFound) String() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetFilePaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFilePaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentSystemTooManyRequests creates a GetFilePaymentConsentSystemTooManyRequests with default headers values
func NewGetFilePaymentConsentSystemTooManyRequests() *GetFilePaymentConsentSystemTooManyRequests {
	return &GetFilePaymentConsentSystemTooManyRequests{}
}

/*
GetFilePaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetFilePaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get file payment consent system too many requests response has a 2xx status code
func (o *GetFilePaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent system too many requests response has a 3xx status code
func (o *GetFilePaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent system too many requests response has a 4xx status code
func (o *GetFilePaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent system too many requests response has a 5xx status code
func (o *GetFilePaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent system too many requests response a status code equal to that given
func (o *GetFilePaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get file payment consent system too many requests response
func (o *GetFilePaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *GetFilePaymentConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetFilePaymentConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/file-payment-consent/{login}][%d] getFilePaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetFilePaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetFilePaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
