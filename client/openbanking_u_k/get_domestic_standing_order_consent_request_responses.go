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

// GetDomesticStandingOrderConsentRequestReader is a Reader for the GetDomesticStandingOrderConsentRequest structure.
type GetDomesticStandingOrderConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDomesticStandingOrderConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDomesticStandingOrderConsentRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDomesticStandingOrderConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetDomesticStandingOrderConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDomesticStandingOrderConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetDomesticStandingOrderConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetDomesticStandingOrderConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetDomesticStandingOrderConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDomesticStandingOrderConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDomesticStandingOrderConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetDomesticStandingOrderConsentRequestOK creates a GetDomesticStandingOrderConsentRequestOK with default headers values
func NewGetDomesticStandingOrderConsentRequestOK() *GetDomesticStandingOrderConsentRequestOK {
	return &GetDomesticStandingOrderConsentRequestOK{}
}

/* GetDomesticStandingOrderConsentRequestOK describes a response with status code 200, with default header values.

DomesticStandingOrderConsentResponse
*/
type GetDomesticStandingOrderConsentRequestOK struct {
	Payload *models.DomesticStandingOrderConsentResponse
}

func (o *GetDomesticStandingOrderConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestOK  %+v", 200, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestOK) GetPayload() *models.DomesticStandingOrderConsentResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DomesticStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestBadRequest creates a GetDomesticStandingOrderConsentRequestBadRequest with default headers values
func NewGetDomesticStandingOrderConsentRequestBadRequest() *GetDomesticStandingOrderConsentRequestBadRequest {
	return &GetDomesticStandingOrderConsentRequestBadRequest{}
}

/* GetDomesticStandingOrderConsentRequestBadRequest describes a response with status code 400, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestBadRequest  %+v", 400, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestUnauthorized creates a GetDomesticStandingOrderConsentRequestUnauthorized with default headers values
func NewGetDomesticStandingOrderConsentRequestUnauthorized() *GetDomesticStandingOrderConsentRequestUnauthorized {
	return &GetDomesticStandingOrderConsentRequestUnauthorized{}
}

/* GetDomesticStandingOrderConsentRequestUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnauthorized  %+v", 401, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestForbidden creates a GetDomesticStandingOrderConsentRequestForbidden with default headers values
func NewGetDomesticStandingOrderConsentRequestForbidden() *GetDomesticStandingOrderConsentRequestForbidden {
	return &GetDomesticStandingOrderConsentRequestForbidden{}
}

/* GetDomesticStandingOrderConsentRequestForbidden describes a response with status code 403, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestForbidden  %+v", 403, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestMethodNotAllowed creates a GetDomesticStandingOrderConsentRequestMethodNotAllowed with default headers values
func NewGetDomesticStandingOrderConsentRequestMethodNotAllowed() *GetDomesticStandingOrderConsentRequestMethodNotAllowed {
	return &GetDomesticStandingOrderConsentRequestMethodNotAllowed{}
}

/* GetDomesticStandingOrderConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestNotAcceptable creates a GetDomesticStandingOrderConsentRequestNotAcceptable with default headers values
func NewGetDomesticStandingOrderConsentRequestNotAcceptable() *GetDomesticStandingOrderConsentRequestNotAcceptable {
	return &GetDomesticStandingOrderConsentRequestNotAcceptable{}
}

/* GetDomesticStandingOrderConsentRequestNotAcceptable describes a response with status code 406, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestNotAcceptable  %+v", 406, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestUnsupportedMediaType creates a GetDomesticStandingOrderConsentRequestUnsupportedMediaType with default headers values
func NewGetDomesticStandingOrderConsentRequestUnsupportedMediaType() *GetDomesticStandingOrderConsentRequestUnsupportedMediaType {
	return &GetDomesticStandingOrderConsentRequestUnsupportedMediaType{}
}

/* GetDomesticStandingOrderConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestTooManyRequests creates a GetDomesticStandingOrderConsentRequestTooManyRequests with default headers values
func NewGetDomesticStandingOrderConsentRequestTooManyRequests() *GetDomesticStandingOrderConsentRequestTooManyRequests {
	return &GetDomesticStandingOrderConsentRequestTooManyRequests{}
}

/* GetDomesticStandingOrderConsentRequestTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentRequestInternalServerError creates a GetDomesticStandingOrderConsentRequestInternalServerError with default headers values
func NewGetDomesticStandingOrderConsentRequestInternalServerError() *GetDomesticStandingOrderConsentRequestInternalServerError {
	return &GetDomesticStandingOrderConsentRequestInternalServerError{}
}

/* GetDomesticStandingOrderConsentRequestInternalServerError describes a response with status code 500, with default header values.

ErrorResponse
*/
type GetDomesticStandingOrderConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

func (o *GetDomesticStandingOrderConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /{tid}/{aid}/open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestInternalServerError  %+v", 500, o.Payload)
}
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
