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

// PatchPaymentConsentReader is a Reader for the PatchPaymentConsent structure.
type PatchPaymentConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchPaymentConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchPaymentConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchPaymentConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchPaymentConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchPaymentConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewPatchPaymentConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewPatchPaymentConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewPatchPaymentConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchPaymentConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchPaymentConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPatchPaymentConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchPaymentConsentOK creates a PatchPaymentConsentOK with default headers values
func NewPatchPaymentConsentOK() *PatchPaymentConsentOK {
	return &PatchPaymentConsentOK{}
}

/*
PatchPaymentConsentOK describes a response with status code 200, with default header values.

Customer payment consent
*/
type PatchPaymentConsentOK struct {
	Payload *models.BrazilCustomerPaymentConsentResponse
}

// IsSuccess returns true when this patch payment consent o k response has a 2xx status code
func (o *PatchPaymentConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch payment consent o k response has a 3xx status code
func (o *PatchPaymentConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent o k response has a 4xx status code
func (o *PatchPaymentConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch payment consent o k response has a 5xx status code
func (o *PatchPaymentConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent o k response a status code equal to that given
func (o *PatchPaymentConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the patch payment consent o k response
func (o *PatchPaymentConsentOK) Code() int {
	return 200
}

func (o *PatchPaymentConsentOK) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentOK  %+v", 200, o.Payload)
}

func (o *PatchPaymentConsentOK) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentOK  %+v", 200, o.Payload)
}

func (o *PatchPaymentConsentOK) GetPayload() *models.BrazilCustomerPaymentConsentResponse {
	return o.Payload
}

func (o *PatchPaymentConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentBadRequest creates a PatchPaymentConsentBadRequest with default headers values
func NewPatchPaymentConsentBadRequest() *PatchPaymentConsentBadRequest {
	return &PatchPaymentConsentBadRequest{}
}

/*
PatchPaymentConsentBadRequest describes a response with status code 400, with default header values.

Error
*/
type PatchPaymentConsentBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent bad request response has a 2xx status code
func (o *PatchPaymentConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent bad request response has a 3xx status code
func (o *PatchPaymentConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent bad request response has a 4xx status code
func (o *PatchPaymentConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent bad request response has a 5xx status code
func (o *PatchPaymentConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent bad request response a status code equal to that given
func (o *PatchPaymentConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the patch payment consent bad request response
func (o *PatchPaymentConsentBadRequest) Code() int {
	return 400
}

func (o *PatchPaymentConsentBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentBadRequest  %+v", 400, o.Payload)
}

func (o *PatchPaymentConsentBadRequest) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentBadRequest  %+v", 400, o.Payload)
}

func (o *PatchPaymentConsentBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentUnauthorized creates a PatchPaymentConsentUnauthorized with default headers values
func NewPatchPaymentConsentUnauthorized() *PatchPaymentConsentUnauthorized {
	return &PatchPaymentConsentUnauthorized{}
}

/*
PatchPaymentConsentUnauthorized describes a response with status code 401, with default header values.

Error
*/
type PatchPaymentConsentUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent unauthorized response has a 2xx status code
func (o *PatchPaymentConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent unauthorized response has a 3xx status code
func (o *PatchPaymentConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent unauthorized response has a 4xx status code
func (o *PatchPaymentConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent unauthorized response has a 5xx status code
func (o *PatchPaymentConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent unauthorized response a status code equal to that given
func (o *PatchPaymentConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the patch payment consent unauthorized response
func (o *PatchPaymentConsentUnauthorized) Code() int {
	return 401
}

func (o *PatchPaymentConsentUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchPaymentConsentUnauthorized) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchPaymentConsentUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentForbidden creates a PatchPaymentConsentForbidden with default headers values
func NewPatchPaymentConsentForbidden() *PatchPaymentConsentForbidden {
	return &PatchPaymentConsentForbidden{}
}

/*
PatchPaymentConsentForbidden describes a response with status code 403, with default header values.

Error
*/
type PatchPaymentConsentForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent forbidden response has a 2xx status code
func (o *PatchPaymentConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent forbidden response has a 3xx status code
func (o *PatchPaymentConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent forbidden response has a 4xx status code
func (o *PatchPaymentConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent forbidden response has a 5xx status code
func (o *PatchPaymentConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent forbidden response a status code equal to that given
func (o *PatchPaymentConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch payment consent forbidden response
func (o *PatchPaymentConsentForbidden) Code() int {
	return 403
}

func (o *PatchPaymentConsentForbidden) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentForbidden  %+v", 403, o.Payload)
}

func (o *PatchPaymentConsentForbidden) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentForbidden  %+v", 403, o.Payload)
}

func (o *PatchPaymentConsentForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentMethodNotAllowed creates a PatchPaymentConsentMethodNotAllowed with default headers values
func NewPatchPaymentConsentMethodNotAllowed() *PatchPaymentConsentMethodNotAllowed {
	return &PatchPaymentConsentMethodNotAllowed{}
}

/*
PatchPaymentConsentMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type PatchPaymentConsentMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent method not allowed response has a 2xx status code
func (o *PatchPaymentConsentMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent method not allowed response has a 3xx status code
func (o *PatchPaymentConsentMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent method not allowed response has a 4xx status code
func (o *PatchPaymentConsentMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent method not allowed response has a 5xx status code
func (o *PatchPaymentConsentMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent method not allowed response a status code equal to that given
func (o *PatchPaymentConsentMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the patch payment consent method not allowed response
func (o *PatchPaymentConsentMethodNotAllowed) Code() int {
	return 405
}

func (o *PatchPaymentConsentMethodNotAllowed) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *PatchPaymentConsentMethodNotAllowed) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *PatchPaymentConsentMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentNotAcceptable creates a PatchPaymentConsentNotAcceptable with default headers values
func NewPatchPaymentConsentNotAcceptable() *PatchPaymentConsentNotAcceptable {
	return &PatchPaymentConsentNotAcceptable{}
}

/*
PatchPaymentConsentNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type PatchPaymentConsentNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent not acceptable response has a 2xx status code
func (o *PatchPaymentConsentNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent not acceptable response has a 3xx status code
func (o *PatchPaymentConsentNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent not acceptable response has a 4xx status code
func (o *PatchPaymentConsentNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent not acceptable response has a 5xx status code
func (o *PatchPaymentConsentNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent not acceptable response a status code equal to that given
func (o *PatchPaymentConsentNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the patch payment consent not acceptable response
func (o *PatchPaymentConsentNotAcceptable) Code() int {
	return 406
}

func (o *PatchPaymentConsentNotAcceptable) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *PatchPaymentConsentNotAcceptable) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *PatchPaymentConsentNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentUnsupportedMediaType creates a PatchPaymentConsentUnsupportedMediaType with default headers values
func NewPatchPaymentConsentUnsupportedMediaType() *PatchPaymentConsentUnsupportedMediaType {
	return &PatchPaymentConsentUnsupportedMediaType{}
}

/*
PatchPaymentConsentUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type PatchPaymentConsentUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent unsupported media type response has a 2xx status code
func (o *PatchPaymentConsentUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent unsupported media type response has a 3xx status code
func (o *PatchPaymentConsentUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent unsupported media type response has a 4xx status code
func (o *PatchPaymentConsentUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent unsupported media type response has a 5xx status code
func (o *PatchPaymentConsentUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent unsupported media type response a status code equal to that given
func (o *PatchPaymentConsentUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the patch payment consent unsupported media type response
func (o *PatchPaymentConsentUnsupportedMediaType) Code() int {
	return 415
}

func (o *PatchPaymentConsentUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchPaymentConsentUnsupportedMediaType) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *PatchPaymentConsentUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentUnprocessableEntity creates a PatchPaymentConsentUnprocessableEntity with default headers values
func NewPatchPaymentConsentUnprocessableEntity() *PatchPaymentConsentUnprocessableEntity {
	return &PatchPaymentConsentUnprocessableEntity{}
}

/*
PatchPaymentConsentUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type PatchPaymentConsentUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent unprocessable entity response has a 2xx status code
func (o *PatchPaymentConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent unprocessable entity response has a 3xx status code
func (o *PatchPaymentConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent unprocessable entity response has a 4xx status code
func (o *PatchPaymentConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent unprocessable entity response has a 5xx status code
func (o *PatchPaymentConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent unprocessable entity response a status code equal to that given
func (o *PatchPaymentConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the patch payment consent unprocessable entity response
func (o *PatchPaymentConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *PatchPaymentConsentUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchPaymentConsentUnprocessableEntity) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *PatchPaymentConsentUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentTooManyRequests creates a PatchPaymentConsentTooManyRequests with default headers values
func NewPatchPaymentConsentTooManyRequests() *PatchPaymentConsentTooManyRequests {
	return &PatchPaymentConsentTooManyRequests{}
}

/*
PatchPaymentConsentTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type PatchPaymentConsentTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent too many requests response has a 2xx status code
func (o *PatchPaymentConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent too many requests response has a 3xx status code
func (o *PatchPaymentConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent too many requests response has a 4xx status code
func (o *PatchPaymentConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch payment consent too many requests response has a 5xx status code
func (o *PatchPaymentConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch payment consent too many requests response a status code equal to that given
func (o *PatchPaymentConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch payment consent too many requests response
func (o *PatchPaymentConsentTooManyRequests) Code() int {
	return 429
}

func (o *PatchPaymentConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchPaymentConsentTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchPaymentConsentTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchPaymentConsentInternalServerError creates a PatchPaymentConsentInternalServerError with default headers values
func NewPatchPaymentConsentInternalServerError() *PatchPaymentConsentInternalServerError {
	return &PatchPaymentConsentInternalServerError{}
}

/*
PatchPaymentConsentInternalServerError describes a response with status code 500, with default header values.

Error
*/
type PatchPaymentConsentInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this patch payment consent internal server error response has a 2xx status code
func (o *PatchPaymentConsentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch payment consent internal server error response has a 3xx status code
func (o *PatchPaymentConsentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch payment consent internal server error response has a 4xx status code
func (o *PatchPaymentConsentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch payment consent internal server error response has a 5xx status code
func (o *PatchPaymentConsentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this patch payment consent internal server error response a status code equal to that given
func (o *PatchPaymentConsentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the patch payment consent internal server error response
func (o *PatchPaymentConsentInternalServerError) Code() int {
	return 500
}

func (o *PatchPaymentConsentInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *PatchPaymentConsentInternalServerError) String() string {
	return fmt.Sprintf("[PATCH /open-banking/payments/v1/consents/{consentID}][%d] patchPaymentConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *PatchPaymentConsentInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *PatchPaymentConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
