// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// GetPaymentConsentDeprecatedReader is a Reader for the GetPaymentConsentDeprecated structure.
type GetPaymentConsentDeprecatedReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPaymentConsentDeprecatedReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPaymentConsentDeprecatedOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetPaymentConsentDeprecatedBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetPaymentConsentDeprecatedUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetPaymentConsentDeprecatedForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetPaymentConsentDeprecatedMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetPaymentConsentDeprecatedNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetPaymentConsentDeprecatedUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetPaymentConsentDeprecatedUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetPaymentConsentDeprecatedTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetPaymentConsentDeprecatedInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetPaymentConsentDeprecatedOK creates a GetPaymentConsentDeprecatedOK with default headers values
func NewGetPaymentConsentDeprecatedOK() *GetPaymentConsentDeprecatedOK {
	return &GetPaymentConsentDeprecatedOK{}
}

/*
GetPaymentConsentDeprecatedOK describes a response with status code 200, with default header values.

Customer payment consent
*/
type GetPaymentConsentDeprecatedOK struct {
	Payload *models.BrazilCustomerPaymentConsentResponse
}

// IsSuccess returns true when this get payment consent deprecated o k response has a 2xx status code
func (o *GetPaymentConsentDeprecatedOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get payment consent deprecated o k response has a 3xx status code
func (o *GetPaymentConsentDeprecatedOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated o k response has a 4xx status code
func (o *GetPaymentConsentDeprecatedOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get payment consent deprecated o k response has a 5xx status code
func (o *GetPaymentConsentDeprecatedOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated o k response a status code equal to that given
func (o *GetPaymentConsentDeprecatedOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get payment consent deprecated o k response
func (o *GetPaymentConsentDeprecatedOK) Code() int {
	return 200
}

func (o *GetPaymentConsentDeprecatedOK) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedOK  %+v", 200, o.Payload)
}

func (o *GetPaymentConsentDeprecatedOK) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedOK  %+v", 200, o.Payload)
}

func (o *GetPaymentConsentDeprecatedOK) GetPayload() *models.BrazilCustomerPaymentConsentResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedBadRequest creates a GetPaymentConsentDeprecatedBadRequest with default headers values
func NewGetPaymentConsentDeprecatedBadRequest() *GetPaymentConsentDeprecatedBadRequest {
	return &GetPaymentConsentDeprecatedBadRequest{}
}

/*
GetPaymentConsentDeprecatedBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetPaymentConsentDeprecatedBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated bad request response has a 2xx status code
func (o *GetPaymentConsentDeprecatedBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated bad request response has a 3xx status code
func (o *GetPaymentConsentDeprecatedBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated bad request response has a 4xx status code
func (o *GetPaymentConsentDeprecatedBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated bad request response has a 5xx status code
func (o *GetPaymentConsentDeprecatedBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated bad request response a status code equal to that given
func (o *GetPaymentConsentDeprecatedBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get payment consent deprecated bad request response
func (o *GetPaymentConsentDeprecatedBadRequest) Code() int {
	return 400
}

func (o *GetPaymentConsentDeprecatedBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedBadRequest  %+v", 400, o.Payload)
}

func (o *GetPaymentConsentDeprecatedBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedBadRequest  %+v", 400, o.Payload)
}

func (o *GetPaymentConsentDeprecatedBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedUnauthorized creates a GetPaymentConsentDeprecatedUnauthorized with default headers values
func NewGetPaymentConsentDeprecatedUnauthorized() *GetPaymentConsentDeprecatedUnauthorized {
	return &GetPaymentConsentDeprecatedUnauthorized{}
}

/*
GetPaymentConsentDeprecatedUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetPaymentConsentDeprecatedUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated unauthorized response has a 2xx status code
func (o *GetPaymentConsentDeprecatedUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated unauthorized response has a 3xx status code
func (o *GetPaymentConsentDeprecatedUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated unauthorized response has a 4xx status code
func (o *GetPaymentConsentDeprecatedUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated unauthorized response has a 5xx status code
func (o *GetPaymentConsentDeprecatedUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated unauthorized response a status code equal to that given
func (o *GetPaymentConsentDeprecatedUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get payment consent deprecated unauthorized response
func (o *GetPaymentConsentDeprecatedUnauthorized) Code() int {
	return 401
}

func (o *GetPaymentConsentDeprecatedUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedForbidden creates a GetPaymentConsentDeprecatedForbidden with default headers values
func NewGetPaymentConsentDeprecatedForbidden() *GetPaymentConsentDeprecatedForbidden {
	return &GetPaymentConsentDeprecatedForbidden{}
}

/*
GetPaymentConsentDeprecatedForbidden describes a response with status code 403, with default header values.

Error
*/
type GetPaymentConsentDeprecatedForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated forbidden response has a 2xx status code
func (o *GetPaymentConsentDeprecatedForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated forbidden response has a 3xx status code
func (o *GetPaymentConsentDeprecatedForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated forbidden response has a 4xx status code
func (o *GetPaymentConsentDeprecatedForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated forbidden response has a 5xx status code
func (o *GetPaymentConsentDeprecatedForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated forbidden response a status code equal to that given
func (o *GetPaymentConsentDeprecatedForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get payment consent deprecated forbidden response
func (o *GetPaymentConsentDeprecatedForbidden) Code() int {
	return 403
}

func (o *GetPaymentConsentDeprecatedForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedForbidden  %+v", 403, o.Payload)
}

func (o *GetPaymentConsentDeprecatedForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedForbidden  %+v", 403, o.Payload)
}

func (o *GetPaymentConsentDeprecatedForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedMethodNotAllowed creates a GetPaymentConsentDeprecatedMethodNotAllowed with default headers values
func NewGetPaymentConsentDeprecatedMethodNotAllowed() *GetPaymentConsentDeprecatedMethodNotAllowed {
	return &GetPaymentConsentDeprecatedMethodNotAllowed{}
}

/*
GetPaymentConsentDeprecatedMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetPaymentConsentDeprecatedMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated method not allowed response has a 2xx status code
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated method not allowed response has a 3xx status code
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated method not allowed response has a 4xx status code
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated method not allowed response has a 5xx status code
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated method not allowed response a status code equal to that given
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get payment consent deprecated method not allowed response
func (o *GetPaymentConsentDeprecatedMethodNotAllowed) Code() int {
	return 405
}

func (o *GetPaymentConsentDeprecatedMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetPaymentConsentDeprecatedMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetPaymentConsentDeprecatedMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedNotAcceptable creates a GetPaymentConsentDeprecatedNotAcceptable with default headers values
func NewGetPaymentConsentDeprecatedNotAcceptable() *GetPaymentConsentDeprecatedNotAcceptable {
	return &GetPaymentConsentDeprecatedNotAcceptable{}
}

/*
GetPaymentConsentDeprecatedNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetPaymentConsentDeprecatedNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated not acceptable response has a 2xx status code
func (o *GetPaymentConsentDeprecatedNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated not acceptable response has a 3xx status code
func (o *GetPaymentConsentDeprecatedNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated not acceptable response has a 4xx status code
func (o *GetPaymentConsentDeprecatedNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated not acceptable response has a 5xx status code
func (o *GetPaymentConsentDeprecatedNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated not acceptable response a status code equal to that given
func (o *GetPaymentConsentDeprecatedNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get payment consent deprecated not acceptable response
func (o *GetPaymentConsentDeprecatedNotAcceptable) Code() int {
	return 406
}

func (o *GetPaymentConsentDeprecatedNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetPaymentConsentDeprecatedNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetPaymentConsentDeprecatedNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedUnsupportedMediaType creates a GetPaymentConsentDeprecatedUnsupportedMediaType with default headers values
func NewGetPaymentConsentDeprecatedUnsupportedMediaType() *GetPaymentConsentDeprecatedUnsupportedMediaType {
	return &GetPaymentConsentDeprecatedUnsupportedMediaType{}
}

/*
GetPaymentConsentDeprecatedUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetPaymentConsentDeprecatedUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated unsupported media type response has a 2xx status code
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated unsupported media type response has a 3xx status code
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated unsupported media type response has a 4xx status code
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated unsupported media type response has a 5xx status code
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated unsupported media type response a status code equal to that given
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get payment consent deprecated unsupported media type response
func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedUnprocessableEntity creates a GetPaymentConsentDeprecatedUnprocessableEntity with default headers values
func NewGetPaymentConsentDeprecatedUnprocessableEntity() *GetPaymentConsentDeprecatedUnprocessableEntity {
	return &GetPaymentConsentDeprecatedUnprocessableEntity{}
}

/*
GetPaymentConsentDeprecatedUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type GetPaymentConsentDeprecatedUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated unprocessable entity response has a 2xx status code
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated unprocessable entity response has a 3xx status code
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated unprocessable entity response has a 4xx status code
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated unprocessable entity response has a 5xx status code
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated unprocessable entity response a status code equal to that given
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the get payment consent deprecated unprocessable entity response
func (o *GetPaymentConsentDeprecatedUnprocessableEntity) Code() int {
	return 422
}

func (o *GetPaymentConsentDeprecatedUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetPaymentConsentDeprecatedUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedTooManyRequests creates a GetPaymentConsentDeprecatedTooManyRequests with default headers values
func NewGetPaymentConsentDeprecatedTooManyRequests() *GetPaymentConsentDeprecatedTooManyRequests {
	return &GetPaymentConsentDeprecatedTooManyRequests{}
}

/*
GetPaymentConsentDeprecatedTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetPaymentConsentDeprecatedTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated too many requests response has a 2xx status code
func (o *GetPaymentConsentDeprecatedTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated too many requests response has a 3xx status code
func (o *GetPaymentConsentDeprecatedTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated too many requests response has a 4xx status code
func (o *GetPaymentConsentDeprecatedTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent deprecated too many requests response has a 5xx status code
func (o *GetPaymentConsentDeprecatedTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent deprecated too many requests response a status code equal to that given
func (o *GetPaymentConsentDeprecatedTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get payment consent deprecated too many requests response
func (o *GetPaymentConsentDeprecatedTooManyRequests) Code() int {
	return 429
}

func (o *GetPaymentConsentDeprecatedTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetPaymentConsentDeprecatedTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetPaymentConsentDeprecatedTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentDeprecatedInternalServerError creates a GetPaymentConsentDeprecatedInternalServerError with default headers values
func NewGetPaymentConsentDeprecatedInternalServerError() *GetPaymentConsentDeprecatedInternalServerError {
	return &GetPaymentConsentDeprecatedInternalServerError{}
}

/*
GetPaymentConsentDeprecatedInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetPaymentConsentDeprecatedInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent deprecated internal server error response has a 2xx status code
func (o *GetPaymentConsentDeprecatedInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent deprecated internal server error response has a 3xx status code
func (o *GetPaymentConsentDeprecatedInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent deprecated internal server error response has a 4xx status code
func (o *GetPaymentConsentDeprecatedInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get payment consent deprecated internal server error response has a 5xx status code
func (o *GetPaymentConsentDeprecatedInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get payment consent deprecated internal server error response a status code equal to that given
func (o *GetPaymentConsentDeprecatedInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get payment consent deprecated internal server error response
func (o *GetPaymentConsentDeprecatedInternalServerError) Code() int {
	return 500
}

func (o *GetPaymentConsentDeprecatedInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPaymentConsentDeprecatedInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking-brasil/open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentDeprecatedInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPaymentConsentDeprecatedInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentDeprecatedInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
