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

// GetInternationalStandingOrderConsentSystemReader is a Reader for the GetInternationalStandingOrderConsentSystem structure.
type GetInternationalStandingOrderConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetInternationalStandingOrderConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetInternationalStandingOrderConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetInternationalStandingOrderConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetInternationalStandingOrderConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetInternationalStandingOrderConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetInternationalStandingOrderConsentSystemOK creates a GetInternationalStandingOrderConsentSystemOK with default headers values
func NewGetInternationalStandingOrderConsentSystemOK() *GetInternationalStandingOrderConsentSystemOK {
	return &GetInternationalStandingOrderConsentSystemOK{}
}

/* GetInternationalStandingOrderConsentSystemOK describes a response with status code 200, with default header values.

GetInternationalStandingOrderConsentResponse
*/
type GetInternationalStandingOrderConsentSystemOK struct {
	Payload *models.GetInternationalStandingOrderConsentResponse
}

func (o *GetInternationalStandingOrderConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemOK  %+v", 200, o.Payload)
}
func (o *GetInternationalStandingOrderConsentSystemOK) GetPayload() *models.GetInternationalStandingOrderConsentResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetInternationalStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemUnauthorized creates a GetInternationalStandingOrderConsentSystemUnauthorized with default headers values
func NewGetInternationalStandingOrderConsentSystemUnauthorized() *GetInternationalStandingOrderConsentSystemUnauthorized {
	return &GetInternationalStandingOrderConsentSystemUnauthorized{}
}

/* GetInternationalStandingOrderConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetInternationalStandingOrderConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemForbidden creates a GetInternationalStandingOrderConsentSystemForbidden with default headers values
func NewGetInternationalStandingOrderConsentSystemForbidden() *GetInternationalStandingOrderConsentSystemForbidden {
	return &GetInternationalStandingOrderConsentSystemForbidden{}
}

/* GetInternationalStandingOrderConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetInternationalStandingOrderConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *GetInternationalStandingOrderConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemNotFound creates a GetInternationalStandingOrderConsentSystemNotFound with default headers values
func NewGetInternationalStandingOrderConsentSystemNotFound() *GetInternationalStandingOrderConsentSystemNotFound {
	return &GetInternationalStandingOrderConsentSystemNotFound{}
}

/* GetInternationalStandingOrderConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetInternationalStandingOrderConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *GetInternationalStandingOrderConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
