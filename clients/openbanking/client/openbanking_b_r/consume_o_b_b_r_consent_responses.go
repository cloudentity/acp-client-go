// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
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

/* ConsumeOBBRConsentOK describes a response with status code 200, with default header values.

BrazilConsent
*/
type ConsumeOBBRConsentOK struct {
	Payload *models.BrazilConsent
}

func (o *ConsumeOBBRConsentOK) Error() string {
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

/* ConsumeOBBRConsentBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ConsumeOBBRConsentBadRequest struct {
	Payload *models.Error
}

func (o *ConsumeOBBRConsentBadRequest) Error() string {
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

/* ConsumeOBBRConsentUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ConsumeOBBRConsentUnauthorized struct {
	Payload *models.Error
}

func (o *ConsumeOBBRConsentUnauthorized) Error() string {
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

/* ConsumeOBBRConsentForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ConsumeOBBRConsentForbidden struct {
	Payload *models.Error
}

func (o *ConsumeOBBRConsentForbidden) Error() string {
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

/* ConsumeOBBRConsentNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ConsumeOBBRConsentNotFound struct {
	Payload *models.Error
}

func (o *ConsumeOBBRConsentNotFound) Error() string {
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

/* ConsumeOBBRConsentTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ConsumeOBBRConsentTooManyRequests struct {
	Payload *models.Error
}

func (o *ConsumeOBBRConsentTooManyRequests) Error() string {
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