// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// GetAccountAccessConsentSystemReader is a Reader for the GetAccountAccessConsentSystem structure.
type GetAccountAccessConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAccountAccessConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAccountAccessConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAccountAccessConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAccountAccessConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAccountAccessConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAccountAccessConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAccountAccessConsentSystemOK creates a GetAccountAccessConsentSystemOK with default headers values
func NewGetAccountAccessConsentSystemOK() *GetAccountAccessConsentSystemOK {
	return &GetAccountAccessConsentSystemOK{}
}

/*
GetAccountAccessConsentSystemOK describes a response with status code 200, with default header values.

GetAccountAccessConsentResponse
*/
type GetAccountAccessConsentSystemOK struct {
	Payload *models.GetAccountAccessConsentResponse
}

// IsSuccess returns true when this get account access consent system o k response has a 2xx status code
func (o *GetAccountAccessConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get account access consent system o k response has a 3xx status code
func (o *GetAccountAccessConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent system o k response has a 4xx status code
func (o *GetAccountAccessConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get account access consent system o k response has a 5xx status code
func (o *GetAccountAccessConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent system o k response a status code equal to that given
func (o *GetAccountAccessConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetAccountAccessConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetAccountAccessConsentSystemOK) String() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetAccountAccessConsentSystemOK) GetPayload() *models.GetAccountAccessConsentResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetAccountAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentSystemUnauthorized creates a GetAccountAccessConsentSystemUnauthorized with default headers values
func NewGetAccountAccessConsentSystemUnauthorized() *GetAccountAccessConsentSystemUnauthorized {
	return &GetAccountAccessConsentSystemUnauthorized{}
}

/*
GetAccountAccessConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetAccountAccessConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get account access consent system unauthorized response has a 2xx status code
func (o *GetAccountAccessConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent system unauthorized response has a 3xx status code
func (o *GetAccountAccessConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent system unauthorized response has a 4xx status code
func (o *GetAccountAccessConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent system unauthorized response has a 5xx status code
func (o *GetAccountAccessConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent system unauthorized response a status code equal to that given
func (o *GetAccountAccessConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetAccountAccessConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAccountAccessConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAccountAccessConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAccountAccessConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentSystemForbidden creates a GetAccountAccessConsentSystemForbidden with default headers values
func NewGetAccountAccessConsentSystemForbidden() *GetAccountAccessConsentSystemForbidden {
	return &GetAccountAccessConsentSystemForbidden{}
}

/*
GetAccountAccessConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetAccountAccessConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get account access consent system forbidden response has a 2xx status code
func (o *GetAccountAccessConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent system forbidden response has a 3xx status code
func (o *GetAccountAccessConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent system forbidden response has a 4xx status code
func (o *GetAccountAccessConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent system forbidden response has a 5xx status code
func (o *GetAccountAccessConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent system forbidden response a status code equal to that given
func (o *GetAccountAccessConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetAccountAccessConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetAccountAccessConsentSystemForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetAccountAccessConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAccountAccessConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentSystemNotFound creates a GetAccountAccessConsentSystemNotFound with default headers values
func NewGetAccountAccessConsentSystemNotFound() *GetAccountAccessConsentSystemNotFound {
	return &GetAccountAccessConsentSystemNotFound{}
}

/*
GetAccountAccessConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetAccountAccessConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get account access consent system not found response has a 2xx status code
func (o *GetAccountAccessConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent system not found response has a 3xx status code
func (o *GetAccountAccessConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent system not found response has a 4xx status code
func (o *GetAccountAccessConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent system not found response has a 5xx status code
func (o *GetAccountAccessConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent system not found response a status code equal to that given
func (o *GetAccountAccessConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetAccountAccessConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetAccountAccessConsentSystemNotFound) String() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetAccountAccessConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAccountAccessConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentSystemTooManyRequests creates a GetAccountAccessConsentSystemTooManyRequests with default headers values
func NewGetAccountAccessConsentSystemTooManyRequests() *GetAccountAccessConsentSystemTooManyRequests {
	return &GetAccountAccessConsentSystemTooManyRequests{}
}

/*
GetAccountAccessConsentSystemTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetAccountAccessConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get account access consent system too many requests response has a 2xx status code
func (o *GetAccountAccessConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent system too many requests response has a 3xx status code
func (o *GetAccountAccessConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent system too many requests response has a 4xx status code
func (o *GetAccountAccessConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent system too many requests response has a 5xx status code
func (o *GetAccountAccessConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent system too many requests response a status code equal to that given
func (o *GetAccountAccessConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetAccountAccessConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAccountAccessConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/account-access-consent/{login}][%d] getAccountAccessConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAccountAccessConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAccountAccessConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
