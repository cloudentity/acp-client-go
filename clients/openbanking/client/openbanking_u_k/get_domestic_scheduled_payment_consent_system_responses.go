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

// GetDomesticScheduledPaymentConsentSystemReader is a Reader for the GetDomesticScheduledPaymentConsentSystem structure.
type GetDomesticScheduledPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDomesticScheduledPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDomesticScheduledPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetDomesticScheduledPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDomesticScheduledPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetDomesticScheduledPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDomesticScheduledPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetDomesticScheduledPaymentConsentSystemOK creates a GetDomesticScheduledPaymentConsentSystemOK with default headers values
func NewGetDomesticScheduledPaymentConsentSystemOK() *GetDomesticScheduledPaymentConsentSystemOK {
	return &GetDomesticScheduledPaymentConsentSystemOK{}
}

/*
GetDomesticScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

GetDomesticScheduledPaymentConsentResponse
*/
type GetDomesticScheduledPaymentConsentSystemOK struct {
	Payload *models.GetDomesticScheduledPaymentConsentResponse
}

// IsSuccess returns true when this get domestic scheduled payment consent system o k response has a 2xx status code
func (o *GetDomesticScheduledPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get domestic scheduled payment consent system o k response has a 3xx status code
func (o *GetDomesticScheduledPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic scheduled payment consent system o k response has a 4xx status code
func (o *GetDomesticScheduledPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic scheduled payment consent system o k response has a 5xx status code
func (o *GetDomesticScheduledPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic scheduled payment consent system o k response a status code equal to that given
func (o *GetDomesticScheduledPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetDomesticScheduledPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemOK) String() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemOK) GetPayload() *models.GetDomesticScheduledPaymentConsentResponse {
	return o.Payload
}

func (o *GetDomesticScheduledPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetDomesticScheduledPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticScheduledPaymentConsentSystemUnauthorized creates a GetDomesticScheduledPaymentConsentSystemUnauthorized with default headers values
func NewGetDomesticScheduledPaymentConsentSystemUnauthorized() *GetDomesticScheduledPaymentConsentSystemUnauthorized {
	return &GetDomesticScheduledPaymentConsentSystemUnauthorized{}
}

/*
GetDomesticScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic scheduled payment consent system unauthorized response has a 2xx status code
func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic scheduled payment consent system unauthorized response has a 3xx status code
func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic scheduled payment consent system unauthorized response has a 4xx status code
func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic scheduled payment consent system unauthorized response has a 5xx status code
func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic scheduled payment consent system unauthorized response a status code equal to that given
func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticScheduledPaymentConsentSystemForbidden creates a GetDomesticScheduledPaymentConsentSystemForbidden with default headers values
func NewGetDomesticScheduledPaymentConsentSystemForbidden() *GetDomesticScheduledPaymentConsentSystemForbidden {
	return &GetDomesticScheduledPaymentConsentSystemForbidden{}
}

/*
GetDomesticScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic scheduled payment consent system forbidden response has a 2xx status code
func (o *GetDomesticScheduledPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic scheduled payment consent system forbidden response has a 3xx status code
func (o *GetDomesticScheduledPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic scheduled payment consent system forbidden response has a 4xx status code
func (o *GetDomesticScheduledPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic scheduled payment consent system forbidden response has a 5xx status code
func (o *GetDomesticScheduledPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic scheduled payment consent system forbidden response a status code equal to that given
func (o *GetDomesticScheduledPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetDomesticScheduledPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticScheduledPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticScheduledPaymentConsentSystemNotFound creates a GetDomesticScheduledPaymentConsentSystemNotFound with default headers values
func NewGetDomesticScheduledPaymentConsentSystemNotFound() *GetDomesticScheduledPaymentConsentSystemNotFound {
	return &GetDomesticScheduledPaymentConsentSystemNotFound{}
}

/*
GetDomesticScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic scheduled payment consent system not found response has a 2xx status code
func (o *GetDomesticScheduledPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic scheduled payment consent system not found response has a 3xx status code
func (o *GetDomesticScheduledPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic scheduled payment consent system not found response has a 4xx status code
func (o *GetDomesticScheduledPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic scheduled payment consent system not found response has a 5xx status code
func (o *GetDomesticScheduledPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic scheduled payment consent system not found response a status code equal to that given
func (o *GetDomesticScheduledPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetDomesticScheduledPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemNotFound) String() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticScheduledPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticScheduledPaymentConsentSystemTooManyRequests creates a GetDomesticScheduledPaymentConsentSystemTooManyRequests with default headers values
func NewGetDomesticScheduledPaymentConsentSystemTooManyRequests() *GetDomesticScheduledPaymentConsentSystemTooManyRequests {
	return &GetDomesticScheduledPaymentConsentSystemTooManyRequests{}
}

/*
GetDomesticScheduledPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic scheduled payment consent system too many requests response has a 2xx status code
func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic scheduled payment consent system too many requests response has a 3xx status code
func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic scheduled payment consent system too many requests response has a 4xx status code
func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic scheduled payment consent system too many requests response has a 5xx status code
func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic scheduled payment consent system too many requests response a status code equal to that given
func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticScheduledPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
