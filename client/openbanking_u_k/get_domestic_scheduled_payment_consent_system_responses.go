// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
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
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetDomesticScheduledPaymentConsentSystemOK creates a GetDomesticScheduledPaymentConsentSystemOK with default headers values
func NewGetDomesticScheduledPaymentConsentSystemOK() *GetDomesticScheduledPaymentConsentSystemOK {
	return &GetDomesticScheduledPaymentConsentSystemOK{}
}

/* GetDomesticScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

GetDomesticScheduledPaymentConsentResponse
*/
type GetDomesticScheduledPaymentConsentSystemOK struct {
	Payload *models.GetDomesticScheduledPaymentConsentResponse
}

func (o *GetDomesticScheduledPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
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

/* GetDomesticScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *GetDomesticScheduledPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
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

/* GetDomesticScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *GetDomesticScheduledPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
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

/* GetDomesticScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetDomesticScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *GetDomesticScheduledPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-scheduled-payment-consent/{login}][%d] getDomesticScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
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
