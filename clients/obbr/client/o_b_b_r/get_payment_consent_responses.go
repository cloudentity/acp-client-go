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

// GetPaymentConsentReader is a Reader for the GetPaymentConsent structure.
type GetPaymentConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPaymentConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPaymentConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetPaymentConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetPaymentConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetPaymentConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetPaymentConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetPaymentConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetPaymentConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetPaymentConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetPaymentConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetPaymentConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/payments/v1/consents/{consentID}] GetPaymentConsent", response, response.Code())
	}
}

// NewGetPaymentConsentOK creates a GetPaymentConsentOK with default headers values
func NewGetPaymentConsentOK() *GetPaymentConsentOK {
	return &GetPaymentConsentOK{}
}

/*
GetPaymentConsentOK describes a response with status code 200, with default header values.

Customer payment consent
*/
type GetPaymentConsentOK struct {
	Payload *models.BrazilCustomerPaymentConsentResponse
}

// IsSuccess returns true when this get payment consent o k response has a 2xx status code
func (o *GetPaymentConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get payment consent o k response has a 3xx status code
func (o *GetPaymentConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent o k response has a 4xx status code
func (o *GetPaymentConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get payment consent o k response has a 5xx status code
func (o *GetPaymentConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent o k response a status code equal to that given
func (o *GetPaymentConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get payment consent o k response
func (o *GetPaymentConsentOK) Code() int {
	return 200
}

func (o *GetPaymentConsentOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentOK  %+v", 200, o.Payload)
}

func (o *GetPaymentConsentOK) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentOK  %+v", 200, o.Payload)
}

func (o *GetPaymentConsentOK) GetPayload() *models.BrazilCustomerPaymentConsentResponse {
	return o.Payload
}

func (o *GetPaymentConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentBadRequest creates a GetPaymentConsentBadRequest with default headers values
func NewGetPaymentConsentBadRequest() *GetPaymentConsentBadRequest {
	return &GetPaymentConsentBadRequest{}
}

/*
GetPaymentConsentBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetPaymentConsentBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent bad request response has a 2xx status code
func (o *GetPaymentConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent bad request response has a 3xx status code
func (o *GetPaymentConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent bad request response has a 4xx status code
func (o *GetPaymentConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent bad request response has a 5xx status code
func (o *GetPaymentConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent bad request response a status code equal to that given
func (o *GetPaymentConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get payment consent bad request response
func (o *GetPaymentConsentBadRequest) Code() int {
	return 400
}

func (o *GetPaymentConsentBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentBadRequest  %+v", 400, o.Payload)
}

func (o *GetPaymentConsentBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentBadRequest  %+v", 400, o.Payload)
}

func (o *GetPaymentConsentBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentUnauthorized creates a GetPaymentConsentUnauthorized with default headers values
func NewGetPaymentConsentUnauthorized() *GetPaymentConsentUnauthorized {
	return &GetPaymentConsentUnauthorized{}
}

/*
GetPaymentConsentUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetPaymentConsentUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent unauthorized response has a 2xx status code
func (o *GetPaymentConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent unauthorized response has a 3xx status code
func (o *GetPaymentConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent unauthorized response has a 4xx status code
func (o *GetPaymentConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent unauthorized response has a 5xx status code
func (o *GetPaymentConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent unauthorized response a status code equal to that given
func (o *GetPaymentConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get payment consent unauthorized response
func (o *GetPaymentConsentUnauthorized) Code() int {
	return 401
}

func (o *GetPaymentConsentUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPaymentConsentUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *GetPaymentConsentUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentForbidden creates a GetPaymentConsentForbidden with default headers values
func NewGetPaymentConsentForbidden() *GetPaymentConsentForbidden {
	return &GetPaymentConsentForbidden{}
}

/*
GetPaymentConsentForbidden describes a response with status code 403, with default header values.

Error
*/
type GetPaymentConsentForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent forbidden response has a 2xx status code
func (o *GetPaymentConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent forbidden response has a 3xx status code
func (o *GetPaymentConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent forbidden response has a 4xx status code
func (o *GetPaymentConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent forbidden response has a 5xx status code
func (o *GetPaymentConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent forbidden response a status code equal to that given
func (o *GetPaymentConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get payment consent forbidden response
func (o *GetPaymentConsentForbidden) Code() int {
	return 403
}

func (o *GetPaymentConsentForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentForbidden  %+v", 403, o.Payload)
}

func (o *GetPaymentConsentForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentForbidden  %+v", 403, o.Payload)
}

func (o *GetPaymentConsentForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentMethodNotAllowed creates a GetPaymentConsentMethodNotAllowed with default headers values
func NewGetPaymentConsentMethodNotAllowed() *GetPaymentConsentMethodNotAllowed {
	return &GetPaymentConsentMethodNotAllowed{}
}

/*
GetPaymentConsentMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetPaymentConsentMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent method not allowed response has a 2xx status code
func (o *GetPaymentConsentMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent method not allowed response has a 3xx status code
func (o *GetPaymentConsentMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent method not allowed response has a 4xx status code
func (o *GetPaymentConsentMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent method not allowed response has a 5xx status code
func (o *GetPaymentConsentMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent method not allowed response a status code equal to that given
func (o *GetPaymentConsentMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get payment consent method not allowed response
func (o *GetPaymentConsentMethodNotAllowed) Code() int {
	return 405
}

func (o *GetPaymentConsentMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetPaymentConsentMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetPaymentConsentMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentNotAcceptable creates a GetPaymentConsentNotAcceptable with default headers values
func NewGetPaymentConsentNotAcceptable() *GetPaymentConsentNotAcceptable {
	return &GetPaymentConsentNotAcceptable{}
}

/*
GetPaymentConsentNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetPaymentConsentNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent not acceptable response has a 2xx status code
func (o *GetPaymentConsentNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent not acceptable response has a 3xx status code
func (o *GetPaymentConsentNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent not acceptable response has a 4xx status code
func (o *GetPaymentConsentNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent not acceptable response has a 5xx status code
func (o *GetPaymentConsentNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent not acceptable response a status code equal to that given
func (o *GetPaymentConsentNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get payment consent not acceptable response
func (o *GetPaymentConsentNotAcceptable) Code() int {
	return 406
}

func (o *GetPaymentConsentNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetPaymentConsentNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetPaymentConsentNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentUnsupportedMediaType creates a GetPaymentConsentUnsupportedMediaType with default headers values
func NewGetPaymentConsentUnsupportedMediaType() *GetPaymentConsentUnsupportedMediaType {
	return &GetPaymentConsentUnsupportedMediaType{}
}

/*
GetPaymentConsentUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetPaymentConsentUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent unsupported media type response has a 2xx status code
func (o *GetPaymentConsentUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent unsupported media type response has a 3xx status code
func (o *GetPaymentConsentUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent unsupported media type response has a 4xx status code
func (o *GetPaymentConsentUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent unsupported media type response has a 5xx status code
func (o *GetPaymentConsentUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent unsupported media type response a status code equal to that given
func (o *GetPaymentConsentUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get payment consent unsupported media type response
func (o *GetPaymentConsentUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetPaymentConsentUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetPaymentConsentUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetPaymentConsentUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentUnprocessableEntity creates a GetPaymentConsentUnprocessableEntity with default headers values
func NewGetPaymentConsentUnprocessableEntity() *GetPaymentConsentUnprocessableEntity {
	return &GetPaymentConsentUnprocessableEntity{}
}

/*
GetPaymentConsentUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type GetPaymentConsentUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent unprocessable entity response has a 2xx status code
func (o *GetPaymentConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent unprocessable entity response has a 3xx status code
func (o *GetPaymentConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent unprocessable entity response has a 4xx status code
func (o *GetPaymentConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent unprocessable entity response has a 5xx status code
func (o *GetPaymentConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent unprocessable entity response a status code equal to that given
func (o *GetPaymentConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the get payment consent unprocessable entity response
func (o *GetPaymentConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *GetPaymentConsentUnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetPaymentConsentUnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetPaymentConsentUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentTooManyRequests creates a GetPaymentConsentTooManyRequests with default headers values
func NewGetPaymentConsentTooManyRequests() *GetPaymentConsentTooManyRequests {
	return &GetPaymentConsentTooManyRequests{}
}

/*
GetPaymentConsentTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetPaymentConsentTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent too many requests response has a 2xx status code
func (o *GetPaymentConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent too many requests response has a 3xx status code
func (o *GetPaymentConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent too many requests response has a 4xx status code
func (o *GetPaymentConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get payment consent too many requests response has a 5xx status code
func (o *GetPaymentConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get payment consent too many requests response a status code equal to that given
func (o *GetPaymentConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get payment consent too many requests response
func (o *GetPaymentConsentTooManyRequests) Code() int {
	return 429
}

func (o *GetPaymentConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetPaymentConsentTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetPaymentConsentTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPaymentConsentInternalServerError creates a GetPaymentConsentInternalServerError with default headers values
func NewGetPaymentConsentInternalServerError() *GetPaymentConsentInternalServerError {
	return &GetPaymentConsentInternalServerError{}
}

/*
GetPaymentConsentInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetPaymentConsentInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get payment consent internal server error response has a 2xx status code
func (o *GetPaymentConsentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get payment consent internal server error response has a 3xx status code
func (o *GetPaymentConsentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get payment consent internal server error response has a 4xx status code
func (o *GetPaymentConsentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get payment consent internal server error response has a 5xx status code
func (o *GetPaymentConsentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get payment consent internal server error response a status code equal to that given
func (o *GetPaymentConsentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get payment consent internal server error response
func (o *GetPaymentConsentInternalServerError) Code() int {
	return 500
}

func (o *GetPaymentConsentInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPaymentConsentInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/payments/v1/consents/{consentID}][%d] getPaymentConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *GetPaymentConsentInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetPaymentConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}