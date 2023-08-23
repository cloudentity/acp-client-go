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

// GetInternationalStandingOrderConsentRequestReader is a Reader for the GetInternationalStandingOrderConsentRequest structure.
type GetInternationalStandingOrderConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetInternationalStandingOrderConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetInternationalStandingOrderConsentRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetInternationalStandingOrderConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetInternationalStandingOrderConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetInternationalStandingOrderConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetInternationalStandingOrderConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetInternationalStandingOrderConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetInternationalStandingOrderConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetInternationalStandingOrderConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetInternationalStandingOrderConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetInternationalStandingOrderConsentRequestOK creates a GetInternationalStandingOrderConsentRequestOK with default headers values
func NewGetInternationalStandingOrderConsentRequestOK() *GetInternationalStandingOrderConsentRequestOK {
	return &GetInternationalStandingOrderConsentRequestOK{}
}

/*
GetInternationalStandingOrderConsentRequestOK describes a response with status code 200, with default header values.

International standing order consent
*/
type GetInternationalStandingOrderConsentRequestOK struct {
	Payload *models.InternationalStandingOrderConsentResponse
}

// IsSuccess returns true when this get international standing order consent request o k response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get international standing order consent request o k response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request o k response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international standing order consent request o k response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request o k response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get international standing order consent request o k response
func (o *GetInternationalStandingOrderConsentRequestOK) Code() int {
	return 200
}

func (o *GetInternationalStandingOrderConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestOK) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestOK) GetPayload() *models.InternationalStandingOrderConsentResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InternationalStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestBadRequest creates a GetInternationalStandingOrderConsentRequestBadRequest with default headers values
func NewGetInternationalStandingOrderConsentRequestBadRequest() *GetInternationalStandingOrderConsentRequestBadRequest {
	return &GetInternationalStandingOrderConsentRequestBadRequest{}
}

/*
GetInternationalStandingOrderConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request bad request response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request bad request response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request bad request response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request bad request response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request bad request response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get international standing order consent request bad request response
func (o *GetInternationalStandingOrderConsentRequestBadRequest) Code() int {
	return 400
}

func (o *GetInternationalStandingOrderConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestUnauthorized creates a GetInternationalStandingOrderConsentRequestUnauthorized with default headers values
func NewGetInternationalStandingOrderConsentRequestUnauthorized() *GetInternationalStandingOrderConsentRequestUnauthorized {
	return &GetInternationalStandingOrderConsentRequestUnauthorized{}
}

/*
GetInternationalStandingOrderConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request unauthorized response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request unauthorized response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request unauthorized response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request unauthorized response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request unauthorized response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get international standing order consent request unauthorized response
func (o *GetInternationalStandingOrderConsentRequestUnauthorized) Code() int {
	return 401
}

func (o *GetInternationalStandingOrderConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestForbidden creates a GetInternationalStandingOrderConsentRequestForbidden with default headers values
func NewGetInternationalStandingOrderConsentRequestForbidden() *GetInternationalStandingOrderConsentRequestForbidden {
	return &GetInternationalStandingOrderConsentRequestForbidden{}
}

/*
GetInternationalStandingOrderConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request forbidden response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request forbidden response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request forbidden response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request forbidden response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request forbidden response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get international standing order consent request forbidden response
func (o *GetInternationalStandingOrderConsentRequestForbidden) Code() int {
	return 403
}

func (o *GetInternationalStandingOrderConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestMethodNotAllowed creates a GetInternationalStandingOrderConsentRequestMethodNotAllowed with default headers values
func NewGetInternationalStandingOrderConsentRequestMethodNotAllowed() *GetInternationalStandingOrderConsentRequestMethodNotAllowed {
	return &GetInternationalStandingOrderConsentRequestMethodNotAllowed{}
}

/*
GetInternationalStandingOrderConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request method not allowed response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request method not allowed response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request method not allowed response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request method not allowed response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request method not allowed response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get international standing order consent request method not allowed response
func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) Code() int {
	return 405
}

func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestNotAcceptable creates a GetInternationalStandingOrderConsentRequestNotAcceptable with default headers values
func NewGetInternationalStandingOrderConsentRequestNotAcceptable() *GetInternationalStandingOrderConsentRequestNotAcceptable {
	return &GetInternationalStandingOrderConsentRequestNotAcceptable{}
}

/*
GetInternationalStandingOrderConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request not acceptable response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request not acceptable response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request not acceptable response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request not acceptable response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request not acceptable response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get international standing order consent request not acceptable response
func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) Code() int {
	return 406
}

func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestUnsupportedMediaType creates a GetInternationalStandingOrderConsentRequestUnsupportedMediaType with default headers values
func NewGetInternationalStandingOrderConsentRequestUnsupportedMediaType() *GetInternationalStandingOrderConsentRequestUnsupportedMediaType {
	return &GetInternationalStandingOrderConsentRequestUnsupportedMediaType{}
}

/*
GetInternationalStandingOrderConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request unsupported media type response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request unsupported media type response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request unsupported media type response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request unsupported media type response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request unsupported media type response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get international standing order consent request unsupported media type response
func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestTooManyRequests creates a GetInternationalStandingOrderConsentRequestTooManyRequests with default headers values
func NewGetInternationalStandingOrderConsentRequestTooManyRequests() *GetInternationalStandingOrderConsentRequestTooManyRequests {
	return &GetInternationalStandingOrderConsentRequestTooManyRequests{}
}

/*
GetInternationalStandingOrderConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request too many requests response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request too many requests response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request too many requests response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent request too many requests response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent request too many requests response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get international standing order consent request too many requests response
func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) Code() int {
	return 429
}

func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentRequestInternalServerError creates a GetInternationalStandingOrderConsentRequestInternalServerError with default headers values
func NewGetInternationalStandingOrderConsentRequestInternalServerError() *GetInternationalStandingOrderConsentRequestInternalServerError {
	return &GetInternationalStandingOrderConsentRequestInternalServerError{}
}

/*
GetInternationalStandingOrderConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetInternationalStandingOrderConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get international standing order consent request internal server error response has a 2xx status code
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent request internal server error response has a 3xx status code
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent request internal server error response has a 4xx status code
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international standing order consent request internal server error response has a 5xx status code
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get international standing order consent request internal server error response a status code equal to that given
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get international standing order consent request internal server error response
func (o *GetInternationalStandingOrderConsentRequestInternalServerError) Code() int {
	return 500
}

func (o *GetInternationalStandingOrderConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/international-standing-order-consents/{consentID}][%d] getInternationalStandingOrderConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetInternationalStandingOrderConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}