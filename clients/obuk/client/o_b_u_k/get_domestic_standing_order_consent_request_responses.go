// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
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
		return nil, runtime.NewAPIError("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}] getDomesticStandingOrderConsentRequest", response, response.Code())
	}
}

// NewGetDomesticStandingOrderConsentRequestOK creates a GetDomesticStandingOrderConsentRequestOK with default headers values
func NewGetDomesticStandingOrderConsentRequestOK() *GetDomesticStandingOrderConsentRequestOK {
	return &GetDomesticStandingOrderConsentRequestOK{}
}

/*
GetDomesticStandingOrderConsentRequestOK describes a response with status code 200, with default header values.

Domestic standing order consent
*/
type GetDomesticStandingOrderConsentRequestOK struct {
	Payload *models.DomesticStandingOrderConsentResponse
}

// IsSuccess returns true when this get domestic standing order consent request o k response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get domestic standing order consent request o k response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request o k response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic standing order consent request o k response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request o k response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get domestic standing order consent request o k response
func (o *GetDomesticStandingOrderConsentRequestOK) Code() int {
	return 200
}

func (o *GetDomesticStandingOrderConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestOK) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestOK  %+v", 200, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request bad request response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request bad request response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request bad request response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request bad request response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request bad request response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get domestic standing order consent request bad request response
func (o *GetDomesticStandingOrderConsentRequestBadRequest) Code() int {
	return 400
}

func (o *GetDomesticStandingOrderConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestBadRequest  %+v", 400, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request unauthorized response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request unauthorized response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request unauthorized response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request unauthorized response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request unauthorized response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get domestic standing order consent request unauthorized response
func (o *GetDomesticStandingOrderConsentRequestUnauthorized) Code() int {
	return 401
}

func (o *GetDomesticStandingOrderConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnauthorized  %+v", 401, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request forbidden response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request forbidden response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request forbidden response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request forbidden response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request forbidden response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get domestic standing order consent request forbidden response
func (o *GetDomesticStandingOrderConsentRequestForbidden) Code() int {
	return 403
}

func (o *GetDomesticStandingOrderConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestForbidden  %+v", 403, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request method not allowed response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request method not allowed response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request method not allowed response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request method not allowed response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request method not allowed response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get domestic standing order consent request method not allowed response
func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) Code() int {
	return 405
}

func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request not acceptable response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request not acceptable response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request not acceptable response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request not acceptable response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request not acceptable response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get domestic standing order consent request not acceptable response
func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) Code() int {
	return 406
}

func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestNotAcceptable  %+v", 406, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request unsupported media type response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request unsupported media type response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request unsupported media type response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request unsupported media type response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request unsupported media type response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get domestic standing order consent request unsupported media type response
func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request too many requests response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request too many requests response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request too many requests response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consent request too many requests response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consent request too many requests response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get domestic standing order consent request too many requests response
func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) Code() int {
	return 429
}

func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestTooManyRequests  %+v", 429, o.Payload)
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

/*
GetDomesticStandingOrderConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetDomesticStandingOrderConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get domestic standing order consent request internal server error response has a 2xx status code
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consent request internal server error response has a 3xx status code
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consent request internal server error response has a 4xx status code
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic standing order consent request internal server error response has a 5xx status code
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get domestic standing order consent request internal server error response a status code equal to that given
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get domestic standing order consent request internal server error response
func (o *GetDomesticStandingOrderConsentRequestInternalServerError) Code() int {
	return 500
}

func (o *GetDomesticStandingOrderConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetDomesticStandingOrderConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/domestic-standing-order-consents/{consentID}][%d] getDomesticStandingOrderConsentRequestInternalServerError  %+v", 500, o.Payload)
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
