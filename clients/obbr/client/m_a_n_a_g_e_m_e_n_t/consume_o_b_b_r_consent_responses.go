// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// ConsumeOBBRConsentReader is a Reader for the ConsumeOBBRConsent structure.
type ConsumeOBBRConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConsumeOBBRConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConsumeOBBRConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewConsumeOBBRConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewConsumeOBBRConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewConsumeOBBRConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewConsumeOBBRConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewConsumeOBBRConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewConsumeOBBRConsentOK creates a ConsumeOBBRConsentOK with default headers values
func NewConsumeOBBRConsentOK() *ConsumeOBBRConsentOK {
	return &ConsumeOBBRConsentOK{}
}

/*
ConsumeOBBRConsentOK describes a response with status code 200, with default header values.

BrazilConsent
*/
type ConsumeOBBRConsentOK struct {
	Payload *models.BrazilConsent
}

// IsSuccess returns true when this consume o b b r consent o k response has a 2xx status code
func (o *ConsumeOBBRConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this consume o b b r consent o k response has a 3xx status code
func (o *ConsumeOBBRConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent o k response has a 4xx status code
func (o *ConsumeOBBRConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this consume o b b r consent o k response has a 5xx status code
func (o *ConsumeOBBRConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent o k response a status code equal to that given
func (o *ConsumeOBBRConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the consume o b b r consent o k response
func (o *ConsumeOBBRConsentOK) Code() int {
	return 200
}

func (o *ConsumeOBBRConsentOK) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentOK  %+v", 200, o.Payload)
}

func (o *ConsumeOBBRConsentOK) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentOK  %+v", 200, o.Payload)
}

func (o *ConsumeOBBRConsentOK) GetPayload() *models.BrazilConsent {
	return o.Payload
}

func (o *ConsumeOBBRConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilConsent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBBRConsentBadRequest creates a ConsumeOBBRConsentBadRequest with default headers values
func NewConsumeOBBRConsentBadRequest() *ConsumeOBBRConsentBadRequest {
	return &ConsumeOBBRConsentBadRequest{}
}

/*
ConsumeOBBRConsentBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ConsumeOBBRConsentBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b b r consent bad request response has a 2xx status code
func (o *ConsumeOBBRConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b b r consent bad request response has a 3xx status code
func (o *ConsumeOBBRConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent bad request response has a 4xx status code
func (o *ConsumeOBBRConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b b r consent bad request response has a 5xx status code
func (o *ConsumeOBBRConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent bad request response a status code equal to that given
func (o *ConsumeOBBRConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the consume o b b r consent bad request response
func (o *ConsumeOBBRConsentBadRequest) Code() int {
	return 400
}

func (o *ConsumeOBBRConsentBadRequest) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentBadRequest  %+v", 400, o.Payload)
}

func (o *ConsumeOBBRConsentBadRequest) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentBadRequest  %+v", 400, o.Payload)
}

func (o *ConsumeOBBRConsentBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBBRConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBBRConsentUnauthorized creates a ConsumeOBBRConsentUnauthorized with default headers values
func NewConsumeOBBRConsentUnauthorized() *ConsumeOBBRConsentUnauthorized {
	return &ConsumeOBBRConsentUnauthorized{}
}

/*
ConsumeOBBRConsentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ConsumeOBBRConsentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b b r consent unauthorized response has a 2xx status code
func (o *ConsumeOBBRConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b b r consent unauthorized response has a 3xx status code
func (o *ConsumeOBBRConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent unauthorized response has a 4xx status code
func (o *ConsumeOBBRConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b b r consent unauthorized response has a 5xx status code
func (o *ConsumeOBBRConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent unauthorized response a status code equal to that given
func (o *ConsumeOBBRConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the consume o b b r consent unauthorized response
func (o *ConsumeOBBRConsentUnauthorized) Code() int {
	return 401
}

func (o *ConsumeOBBRConsentUnauthorized) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *ConsumeOBBRConsentUnauthorized) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *ConsumeOBBRConsentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBBRConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBBRConsentForbidden creates a ConsumeOBBRConsentForbidden with default headers values
func NewConsumeOBBRConsentForbidden() *ConsumeOBBRConsentForbidden {
	return &ConsumeOBBRConsentForbidden{}
}

/*
ConsumeOBBRConsentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ConsumeOBBRConsentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b b r consent forbidden response has a 2xx status code
func (o *ConsumeOBBRConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b b r consent forbidden response has a 3xx status code
func (o *ConsumeOBBRConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent forbidden response has a 4xx status code
func (o *ConsumeOBBRConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b b r consent forbidden response has a 5xx status code
func (o *ConsumeOBBRConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent forbidden response a status code equal to that given
func (o *ConsumeOBBRConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the consume o b b r consent forbidden response
func (o *ConsumeOBBRConsentForbidden) Code() int {
	return 403
}

func (o *ConsumeOBBRConsentForbidden) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentForbidden  %+v", 403, o.Payload)
}

func (o *ConsumeOBBRConsentForbidden) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentForbidden  %+v", 403, o.Payload)
}

func (o *ConsumeOBBRConsentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBBRConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBBRConsentNotFound creates a ConsumeOBBRConsentNotFound with default headers values
func NewConsumeOBBRConsentNotFound() *ConsumeOBBRConsentNotFound {
	return &ConsumeOBBRConsentNotFound{}
}

/*
ConsumeOBBRConsentNotFound describes a response with status code 404, with default header values.

Not found
*/
type ConsumeOBBRConsentNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b b r consent not found response has a 2xx status code
func (o *ConsumeOBBRConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b b r consent not found response has a 3xx status code
func (o *ConsumeOBBRConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent not found response has a 4xx status code
func (o *ConsumeOBBRConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b b r consent not found response has a 5xx status code
func (o *ConsumeOBBRConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent not found response a status code equal to that given
func (o *ConsumeOBBRConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the consume o b b r consent not found response
func (o *ConsumeOBBRConsentNotFound) Code() int {
	return 404
}

func (o *ConsumeOBBRConsentNotFound) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentNotFound  %+v", 404, o.Payload)
}

func (o *ConsumeOBBRConsentNotFound) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentNotFound  %+v", 404, o.Payload)
}

func (o *ConsumeOBBRConsentNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBBRConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBBRConsentTooManyRequests creates a ConsumeOBBRConsentTooManyRequests with default headers values
func NewConsumeOBBRConsentTooManyRequests() *ConsumeOBBRConsentTooManyRequests {
	return &ConsumeOBBRConsentTooManyRequests{}
}

/*
ConsumeOBBRConsentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ConsumeOBBRConsentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b b r consent too many requests response has a 2xx status code
func (o *ConsumeOBBRConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b b r consent too many requests response has a 3xx status code
func (o *ConsumeOBBRConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b b r consent too many requests response has a 4xx status code
func (o *ConsumeOBBRConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b b r consent too many requests response has a 5xx status code
func (o *ConsumeOBBRConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b b r consent too many requests response a status code equal to that given
func (o *ConsumeOBBRConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the consume o b b r consent too many requests response
func (o *ConsumeOBBRConsentTooManyRequests) Code() int {
	return 429
}

func (o *ConsumeOBBRConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *ConsumeOBBRConsentTooManyRequests) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/open-banking-brasil/consents/{consentID}/consume][%d] consumeOBBRConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *ConsumeOBBRConsentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBBRConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
