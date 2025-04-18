// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// ConsumeOBUKConsentReader is a Reader for the ConsumeOBUKConsent structure.
type ConsumeOBUKConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConsumeOBUKConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConsumeOBUKConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewConsumeOBUKConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewConsumeOBUKConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewConsumeOBUKConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewConsumeOBUKConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewConsumeOBUKConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/open-banking/consents/{consentID}/consume] consumeOBUKConsent", response, response.Code())
	}
}

// NewConsumeOBUKConsentOK creates a ConsumeOBUKConsentOK with default headers values
func NewConsumeOBUKConsentOK() *ConsumeOBUKConsentOK {
	return &ConsumeOBUKConsentOK{}
}

/*
ConsumeOBUKConsentOK describes a response with status code 200, with default header values.

UKConsent
*/
type ConsumeOBUKConsentOK struct {
	Payload *models.UKConsent
}

// IsSuccess returns true when this consume o b u k consent o k response has a 2xx status code
func (o *ConsumeOBUKConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this consume o b u k consent o k response has a 3xx status code
func (o *ConsumeOBUKConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent o k response has a 4xx status code
func (o *ConsumeOBUKConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this consume o b u k consent o k response has a 5xx status code
func (o *ConsumeOBUKConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent o k response a status code equal to that given
func (o *ConsumeOBUKConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the consume o b u k consent o k response
func (o *ConsumeOBUKConsentOK) Code() int {
	return 200
}

func (o *ConsumeOBUKConsentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentOK %s", 200, payload)
}

func (o *ConsumeOBUKConsentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentOK %s", 200, payload)
}

func (o *ConsumeOBUKConsentOK) GetPayload() *models.UKConsent {
	return o.Payload
}

func (o *ConsumeOBUKConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.UKConsent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBUKConsentBadRequest creates a ConsumeOBUKConsentBadRequest with default headers values
func NewConsumeOBUKConsentBadRequest() *ConsumeOBUKConsentBadRequest {
	return &ConsumeOBUKConsentBadRequest{}
}

/*
ConsumeOBUKConsentBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ConsumeOBUKConsentBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b u k consent bad request response has a 2xx status code
func (o *ConsumeOBUKConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b u k consent bad request response has a 3xx status code
func (o *ConsumeOBUKConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent bad request response has a 4xx status code
func (o *ConsumeOBUKConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b u k consent bad request response has a 5xx status code
func (o *ConsumeOBUKConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent bad request response a status code equal to that given
func (o *ConsumeOBUKConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the consume o b u k consent bad request response
func (o *ConsumeOBUKConsentBadRequest) Code() int {
	return 400
}

func (o *ConsumeOBUKConsentBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentBadRequest %s", 400, payload)
}

func (o *ConsumeOBUKConsentBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentBadRequest %s", 400, payload)
}

func (o *ConsumeOBUKConsentBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBUKConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBUKConsentUnauthorized creates a ConsumeOBUKConsentUnauthorized with default headers values
func NewConsumeOBUKConsentUnauthorized() *ConsumeOBUKConsentUnauthorized {
	return &ConsumeOBUKConsentUnauthorized{}
}

/*
ConsumeOBUKConsentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ConsumeOBUKConsentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b u k consent unauthorized response has a 2xx status code
func (o *ConsumeOBUKConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b u k consent unauthorized response has a 3xx status code
func (o *ConsumeOBUKConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent unauthorized response has a 4xx status code
func (o *ConsumeOBUKConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b u k consent unauthorized response has a 5xx status code
func (o *ConsumeOBUKConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent unauthorized response a status code equal to that given
func (o *ConsumeOBUKConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the consume o b u k consent unauthorized response
func (o *ConsumeOBUKConsentUnauthorized) Code() int {
	return 401
}

func (o *ConsumeOBUKConsentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentUnauthorized %s", 401, payload)
}

func (o *ConsumeOBUKConsentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentUnauthorized %s", 401, payload)
}

func (o *ConsumeOBUKConsentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBUKConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBUKConsentForbidden creates a ConsumeOBUKConsentForbidden with default headers values
func NewConsumeOBUKConsentForbidden() *ConsumeOBUKConsentForbidden {
	return &ConsumeOBUKConsentForbidden{}
}

/*
ConsumeOBUKConsentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ConsumeOBUKConsentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b u k consent forbidden response has a 2xx status code
func (o *ConsumeOBUKConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b u k consent forbidden response has a 3xx status code
func (o *ConsumeOBUKConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent forbidden response has a 4xx status code
func (o *ConsumeOBUKConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b u k consent forbidden response has a 5xx status code
func (o *ConsumeOBUKConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent forbidden response a status code equal to that given
func (o *ConsumeOBUKConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the consume o b u k consent forbidden response
func (o *ConsumeOBUKConsentForbidden) Code() int {
	return 403
}

func (o *ConsumeOBUKConsentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentForbidden %s", 403, payload)
}

func (o *ConsumeOBUKConsentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentForbidden %s", 403, payload)
}

func (o *ConsumeOBUKConsentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBUKConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBUKConsentNotFound creates a ConsumeOBUKConsentNotFound with default headers values
func NewConsumeOBUKConsentNotFound() *ConsumeOBUKConsentNotFound {
	return &ConsumeOBUKConsentNotFound{}
}

/*
ConsumeOBUKConsentNotFound describes a response with status code 404, with default header values.

Not found
*/
type ConsumeOBUKConsentNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b u k consent not found response has a 2xx status code
func (o *ConsumeOBUKConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b u k consent not found response has a 3xx status code
func (o *ConsumeOBUKConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent not found response has a 4xx status code
func (o *ConsumeOBUKConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b u k consent not found response has a 5xx status code
func (o *ConsumeOBUKConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent not found response a status code equal to that given
func (o *ConsumeOBUKConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the consume o b u k consent not found response
func (o *ConsumeOBUKConsentNotFound) Code() int {
	return 404
}

func (o *ConsumeOBUKConsentNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentNotFound %s", 404, payload)
}

func (o *ConsumeOBUKConsentNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentNotFound %s", 404, payload)
}

func (o *ConsumeOBUKConsentNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBUKConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConsumeOBUKConsentTooManyRequests creates a ConsumeOBUKConsentTooManyRequests with default headers values
func NewConsumeOBUKConsentTooManyRequests() *ConsumeOBUKConsentTooManyRequests {
	return &ConsumeOBUKConsentTooManyRequests{}
}

/*
ConsumeOBUKConsentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ConsumeOBUKConsentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this consume o b u k consent too many requests response has a 2xx status code
func (o *ConsumeOBUKConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this consume o b u k consent too many requests response has a 3xx status code
func (o *ConsumeOBUKConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this consume o b u k consent too many requests response has a 4xx status code
func (o *ConsumeOBUKConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this consume o b u k consent too many requests response has a 5xx status code
func (o *ConsumeOBUKConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this consume o b u k consent too many requests response a status code equal to that given
func (o *ConsumeOBUKConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the consume o b u k consent too many requests response
func (o *ConsumeOBUKConsentTooManyRequests) Code() int {
	return 429
}

func (o *ConsumeOBUKConsentTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentTooManyRequests %s", 429, payload)
}

func (o *ConsumeOBUKConsentTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/open-banking/consents/{consentID}/consume][%d] consumeOBUKConsentTooManyRequests %s", 429, payload)
}

func (o *ConsumeOBUKConsentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ConsumeOBUKConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
