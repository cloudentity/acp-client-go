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

// GetInternationalPaymentConsentRequestReader is a Reader for the GetInternationalPaymentConsentRequest structure.
type GetInternationalPaymentConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetInternationalPaymentConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetInternationalPaymentConsentRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetInternationalPaymentConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetInternationalPaymentConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetInternationalPaymentConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetInternationalPaymentConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetInternationalPaymentConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetInternationalPaymentConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetInternationalPaymentConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetInternationalPaymentConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetInternationalPaymentConsentRequestOK creates a GetInternationalPaymentConsentRequestOK with default headers values
func NewGetInternationalPaymentConsentRequestOK() *GetInternationalPaymentConsentRequestOK {
	return &GetInternationalPaymentConsentRequestOK{}
}

/*
GetInternationalPaymentConsentRequestOK describes a response with status code 200, with default header values.

International payment consent
*/
type GetInternationalPaymentConsentRequestOK struct {
	Payload *models.InternationalPaymentConsentResponse
}

// IsSuccess returns true when this get international payment consent request o k response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get international payment consent request o k response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request o k response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international payment consent request o k response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request o k response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetInternationalPaymentConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestOK) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestOK) GetPayload() *models.InternationalPaymentConsentResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InternationalPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestBadRequest creates a GetInternationalPaymentConsentRequestBadRequest with default headers values
func NewGetInternationalPaymentConsentRequestBadRequest() *GetInternationalPaymentConsentRequestBadRequest {
	return &GetInternationalPaymentConsentRequestBadRequest{}
}

/*
GetInternationalPaymentConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request bad request response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request bad request response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request bad request response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request bad request response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request bad request response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *GetInternationalPaymentConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestUnauthorized creates a GetInternationalPaymentConsentRequestUnauthorized with default headers values
func NewGetInternationalPaymentConsentRequestUnauthorized() *GetInternationalPaymentConsentRequestUnauthorized {
	return &GetInternationalPaymentConsentRequestUnauthorized{}
}

/*
GetInternationalPaymentConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request unauthorized response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request unauthorized response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request unauthorized response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request unauthorized response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request unauthorized response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetInternationalPaymentConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestForbidden creates a GetInternationalPaymentConsentRequestForbidden with default headers values
func NewGetInternationalPaymentConsentRequestForbidden() *GetInternationalPaymentConsentRequestForbidden {
	return &GetInternationalPaymentConsentRequestForbidden{}
}

/*
GetInternationalPaymentConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request forbidden response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request forbidden response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request forbidden response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request forbidden response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request forbidden response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetInternationalPaymentConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestMethodNotAllowed creates a GetInternationalPaymentConsentRequestMethodNotAllowed with default headers values
func NewGetInternationalPaymentConsentRequestMethodNotAllowed() *GetInternationalPaymentConsentRequestMethodNotAllowed {
	return &GetInternationalPaymentConsentRequestMethodNotAllowed{}
}

/*
GetInternationalPaymentConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request method not allowed response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request method not allowed response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request method not allowed response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request method not allowed response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request method not allowed response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestNotAcceptable creates a GetInternationalPaymentConsentRequestNotAcceptable with default headers values
func NewGetInternationalPaymentConsentRequestNotAcceptable() *GetInternationalPaymentConsentRequestNotAcceptable {
	return &GetInternationalPaymentConsentRequestNotAcceptable{}
}

/*
GetInternationalPaymentConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request not acceptable response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request not acceptable response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request not acceptable response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request not acceptable response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request not acceptable response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

func (o *GetInternationalPaymentConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestUnsupportedMediaType creates a GetInternationalPaymentConsentRequestUnsupportedMediaType with default headers values
func NewGetInternationalPaymentConsentRequestUnsupportedMediaType() *GetInternationalPaymentConsentRequestUnsupportedMediaType {
	return &GetInternationalPaymentConsentRequestUnsupportedMediaType{}
}

/*
GetInternationalPaymentConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request unsupported media type response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request unsupported media type response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request unsupported media type response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request unsupported media type response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request unsupported media type response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestTooManyRequests creates a GetInternationalPaymentConsentRequestTooManyRequests with default headers values
func NewGetInternationalPaymentConsentRequestTooManyRequests() *GetInternationalPaymentConsentRequestTooManyRequests {
	return &GetInternationalPaymentConsentRequestTooManyRequests{}
}

/*
GetInternationalPaymentConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request too many requests response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request too many requests response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request too many requests response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international payment consent request too many requests response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get international payment consent request too many requests response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetInternationalPaymentConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalPaymentConsentRequestInternalServerError creates a GetInternationalPaymentConsentRequestInternalServerError with default headers values
func NewGetInternationalPaymentConsentRequestInternalServerError() *GetInternationalPaymentConsentRequestInternalServerError {
	return &GetInternationalPaymentConsentRequestInternalServerError{}
}

/*
GetInternationalPaymentConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetInternationalPaymentConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international payment consent request internal server error response has a 2xx status code
func (o *GetInternationalPaymentConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international payment consent request internal server error response has a 3xx status code
func (o *GetInternationalPaymentConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international payment consent request internal server error response has a 4xx status code
func (o *GetInternationalPaymentConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international payment consent request internal server error response has a 5xx status code
func (o *GetInternationalPaymentConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get international payment consent request internal server error response a status code equal to that given
func (o *GetInternationalPaymentConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *GetInternationalPaymentConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-payment-consents/{consentID}][%d] getInternationalPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalPaymentConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalPaymentConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
