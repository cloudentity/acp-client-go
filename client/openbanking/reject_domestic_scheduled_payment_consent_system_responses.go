// Code generated by go-swagger; DO NOT EDIT.

package openbanking

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// RejectDomesticScheduledPaymentConsentSystemReader is a Reader for the RejectDomesticScheduledPaymentConsentSystem structure.
type RejectDomesticScheduledPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectDomesticScheduledPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectDomesticScheduledPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectDomesticScheduledPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectDomesticScheduledPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectDomesticScheduledPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectDomesticScheduledPaymentConsentSystemOK creates a RejectDomesticScheduledPaymentConsentSystemOK with default headers values
func NewRejectDomesticScheduledPaymentConsentSystemOK() *RejectDomesticScheduledPaymentConsentSystemOK {
	return &RejectDomesticScheduledPaymentConsentSystemOK{}
}

/* RejectDomesticScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

DomesticScheduledPaymentConsentRejected
*/
type RejectDomesticScheduledPaymentConsentSystemOK struct {
	Payload *models.DomesticScheduledPaymentConsentRejected
}

func (o *RejectDomesticScheduledPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/reject][%d] rejectDomesticScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}
func (o *RejectDomesticScheduledPaymentConsentSystemOK) GetPayload() *models.DomesticScheduledPaymentConsentRejected {
	return o.Payload
}

func (o *RejectDomesticScheduledPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DomesticScheduledPaymentConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectDomesticScheduledPaymentConsentSystemUnauthorized creates a RejectDomesticScheduledPaymentConsentSystemUnauthorized with default headers values
func NewRejectDomesticScheduledPaymentConsentSystemUnauthorized() *RejectDomesticScheduledPaymentConsentSystemUnauthorized {
	return &RejectDomesticScheduledPaymentConsentSystemUnauthorized{}
}

/* RejectDomesticScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RejectDomesticScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *RejectDomesticScheduledPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/reject][%d] rejectDomesticScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *RejectDomesticScheduledPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectDomesticScheduledPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectDomesticScheduledPaymentConsentSystemForbidden creates a RejectDomesticScheduledPaymentConsentSystemForbidden with default headers values
func NewRejectDomesticScheduledPaymentConsentSystemForbidden() *RejectDomesticScheduledPaymentConsentSystemForbidden {
	return &RejectDomesticScheduledPaymentConsentSystemForbidden{}
}

/* RejectDomesticScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RejectDomesticScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *RejectDomesticScheduledPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/reject][%d] rejectDomesticScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *RejectDomesticScheduledPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectDomesticScheduledPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectDomesticScheduledPaymentConsentSystemNotFound creates a RejectDomesticScheduledPaymentConsentSystemNotFound with default headers values
func NewRejectDomesticScheduledPaymentConsentSystemNotFound() *RejectDomesticScheduledPaymentConsentSystemNotFound {
	return &RejectDomesticScheduledPaymentConsentSystemNotFound{}
}

/* RejectDomesticScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RejectDomesticScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *RejectDomesticScheduledPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}/reject][%d] rejectDomesticScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *RejectDomesticScheduledPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectDomesticScheduledPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
