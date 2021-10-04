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

// GetDomesticStandingOrderConsentSystemReader is a Reader for the GetDomesticStandingOrderConsentSystem structure.
type GetDomesticStandingOrderConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDomesticStandingOrderConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDomesticStandingOrderConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetDomesticStandingOrderConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDomesticStandingOrderConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetDomesticStandingOrderConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetDomesticStandingOrderConsentSystemOK creates a GetDomesticStandingOrderConsentSystemOK with default headers values
func NewGetDomesticStandingOrderConsentSystemOK() *GetDomesticStandingOrderConsentSystemOK {
	return &GetDomesticStandingOrderConsentSystemOK{}
}

/* GetDomesticStandingOrderConsentSystemOK describes a response with status code 200, with default header values.

GetDomesticStandingOrderConsentResponse
*/
type GetDomesticStandingOrderConsentSystemOK struct {
	Payload *models.GetDomesticStandingOrderConsentResponse
}

func (o *GetDomesticStandingOrderConsentSystemOK) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-standing-order-consent/{login}][%d] getDomesticStandingOrderConsentSystemOK  %+v", 200, o.Payload)
}
func (o *GetDomesticStandingOrderConsentSystemOK) GetPayload() *models.GetDomesticStandingOrderConsentResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetDomesticStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentSystemUnauthorized creates a GetDomesticStandingOrderConsentSystemUnauthorized with default headers values
func NewGetDomesticStandingOrderConsentSystemUnauthorized() *GetDomesticStandingOrderConsentSystemUnauthorized {
	return &GetDomesticStandingOrderConsentSystemUnauthorized{}
}

/* GetDomesticStandingOrderConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetDomesticStandingOrderConsentSystemUnauthorized struct {
	Payload *models.Error
}

func (o *GetDomesticStandingOrderConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-standing-order-consent/{login}][%d] getDomesticStandingOrderConsentSystemUnauthorized  %+v", 401, o.Payload)
}
func (o *GetDomesticStandingOrderConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentSystemForbidden creates a GetDomesticStandingOrderConsentSystemForbidden with default headers values
func NewGetDomesticStandingOrderConsentSystemForbidden() *GetDomesticStandingOrderConsentSystemForbidden {
	return &GetDomesticStandingOrderConsentSystemForbidden{}
}

/* GetDomesticStandingOrderConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetDomesticStandingOrderConsentSystemForbidden struct {
	Payload *models.Error
}

func (o *GetDomesticStandingOrderConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-standing-order-consent/{login}][%d] getDomesticStandingOrderConsentSystemForbidden  %+v", 403, o.Payload)
}
func (o *GetDomesticStandingOrderConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentSystemNotFound creates a GetDomesticStandingOrderConsentSystemNotFound with default headers values
func NewGetDomesticStandingOrderConsentSystemNotFound() *GetDomesticStandingOrderConsentSystemNotFound {
	return &GetDomesticStandingOrderConsentSystemNotFound{}
}

/* GetDomesticStandingOrderConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetDomesticStandingOrderConsentSystemNotFound struct {
	Payload *models.Error
}

func (o *GetDomesticStandingOrderConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[GET /api/system/{tid}/open-banking/domestic-standing-order-consent/{login}][%d] getDomesticStandingOrderConsentSystemNotFound  %+v", 404, o.Payload)
}
func (o *GetDomesticStandingOrderConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
