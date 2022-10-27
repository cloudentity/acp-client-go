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

// GetInternationalScheduledPaymentConsentRequestReader is a Reader for the GetInternationalScheduledPaymentConsentRequest structure.
type GetInternationalScheduledPaymentConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetInternationalScheduledPaymentConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetInternationalScheduledPaymentConsentRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetInternationalScheduledPaymentConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetInternationalScheduledPaymentConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetInternationalScheduledPaymentConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetInternationalScheduledPaymentConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetInternationalScheduledPaymentConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetInternationalScheduledPaymentConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetInternationalScheduledPaymentConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetInternationalScheduledPaymentConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetInternationalScheduledPaymentConsentRequestOK creates a GetInternationalScheduledPaymentConsentRequestOK with default headers values
func NewGetInternationalScheduledPaymentConsentRequestOK() *GetInternationalScheduledPaymentConsentRequestOK {
	return &GetInternationalScheduledPaymentConsentRequestOK{}
}

/*
GetInternationalScheduledPaymentConsentRequestOK describes a response with status code 200, with default header values.

International scheduler payment consent
*/
type GetInternationalScheduledPaymentConsentRequestOK struct {
	Payload *models.InternationalScheduledPaymentConsentResponse
}

// IsSuccess returns true when this get international scheduled payment consent request o k response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get international scheduled payment consent request o k response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request o k response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international scheduled payment consent request o k response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request o k response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetInternationalScheduledPaymentConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestOK) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestOK) GetPayload() *models.InternationalScheduledPaymentConsentResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InternationalScheduledPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestBadRequest creates a GetInternationalScheduledPaymentConsentRequestBadRequest with default headers values
func NewGetInternationalScheduledPaymentConsentRequestBadRequest() *GetInternationalScheduledPaymentConsentRequestBadRequest {
	return &GetInternationalScheduledPaymentConsentRequestBadRequest{}
}

/*
GetInternationalScheduledPaymentConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request bad request response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request bad request response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request bad request response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request bad request response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request bad request response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestUnauthorized creates a GetInternationalScheduledPaymentConsentRequestUnauthorized with default headers values
func NewGetInternationalScheduledPaymentConsentRequestUnauthorized() *GetInternationalScheduledPaymentConsentRequestUnauthorized {
	return &GetInternationalScheduledPaymentConsentRequestUnauthorized{}
}

/*
GetInternationalScheduledPaymentConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request unauthorized response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request unauthorized response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request unauthorized response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request unauthorized response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request unauthorized response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestForbidden creates a GetInternationalScheduledPaymentConsentRequestForbidden with default headers values
func NewGetInternationalScheduledPaymentConsentRequestForbidden() *GetInternationalScheduledPaymentConsentRequestForbidden {
	return &GetInternationalScheduledPaymentConsentRequestForbidden{}
}

/*
GetInternationalScheduledPaymentConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request forbidden response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request forbidden response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request forbidden response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request forbidden response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request forbidden response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetInternationalScheduledPaymentConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestMethodNotAllowed creates a GetInternationalScheduledPaymentConsentRequestMethodNotAllowed with default headers values
func NewGetInternationalScheduledPaymentConsentRequestMethodNotAllowed() *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed {
	return &GetInternationalScheduledPaymentConsentRequestMethodNotAllowed{}
}

/*
GetInternationalScheduledPaymentConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request method not allowed response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request method not allowed response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request method not allowed response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request method not allowed response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request method not allowed response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestNotAcceptable creates a GetInternationalScheduledPaymentConsentRequestNotAcceptable with default headers values
func NewGetInternationalScheduledPaymentConsentRequestNotAcceptable() *GetInternationalScheduledPaymentConsentRequestNotAcceptable {
	return &GetInternationalScheduledPaymentConsentRequestNotAcceptable{}
}

/*
GetInternationalScheduledPaymentConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request not acceptable response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request not acceptable response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request not acceptable response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request not acceptable response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request not acceptable response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestUnsupportedMediaType creates a GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType with default headers values
func NewGetInternationalScheduledPaymentConsentRequestUnsupportedMediaType() *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType {
	return &GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType{}
}

/*
GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request unsupported media type response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request unsupported media type response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request unsupported media type response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request unsupported media type response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request unsupported media type response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestTooManyRequests creates a GetInternationalScheduledPaymentConsentRequestTooManyRequests with default headers values
func NewGetInternationalScheduledPaymentConsentRequestTooManyRequests() *GetInternationalScheduledPaymentConsentRequestTooManyRequests {
	return &GetInternationalScheduledPaymentConsentRequestTooManyRequests{}
}

/*
GetInternationalScheduledPaymentConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request too many requests response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request too many requests response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request too many requests response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international scheduled payment consent request too many requests response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get international scheduled payment consent request too many requests response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalScheduledPaymentConsentRequestInternalServerError creates a GetInternationalScheduledPaymentConsentRequestInternalServerError with default headers values
func NewGetInternationalScheduledPaymentConsentRequestInternalServerError() *GetInternationalScheduledPaymentConsentRequestInternalServerError {
	return &GetInternationalScheduledPaymentConsentRequestInternalServerError{}
}

/*
GetInternationalScheduledPaymentConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetInternationalScheduledPaymentConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international scheduled payment consent request internal server error response has a 2xx status code
func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international scheduled payment consent request internal server error response has a 3xx status code
func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international scheduled payment consent request internal server error response has a 4xx status code
func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international scheduled payment consent request internal server error response has a 5xx status code
func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get international scheduled payment consent request internal server error response a status code equal to that given
func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-scheduled-payment-consents/{consentID}][%d] getInternationalScheduledPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalScheduledPaymentConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
