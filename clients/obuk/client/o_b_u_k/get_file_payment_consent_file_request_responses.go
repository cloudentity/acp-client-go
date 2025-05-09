// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// GetFilePaymentConsentFileRequestReader is a Reader for the GetFilePaymentConsentFileRequest structure.
type GetFilePaymentConsentFileRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFilePaymentConsentFileRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFilePaymentConsentFileRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetFilePaymentConsentFileRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetFilePaymentConsentFileRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetFilePaymentConsentFileRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetFilePaymentConsentFileRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetFilePaymentConsentFileRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetFilePaymentConsentFileRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetFilePaymentConsentFileRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetFilePaymentConsentFileRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file] getFilePaymentConsentFileRequest", response, response.Code())
	}
}

// NewGetFilePaymentConsentFileRequestOK creates a GetFilePaymentConsentFileRequestOK with default headers values
func NewGetFilePaymentConsentFileRequestOK() *GetFilePaymentConsentFileRequestOK {
	return &GetFilePaymentConsentFileRequestOK{}
}

/*
GetFilePaymentConsentFileRequestOK describes a response with status code 200, with default header values.

File payment consent file
*/
type GetFilePaymentConsentFileRequestOK struct {
	Payload models.FilePaymentConsentFileResponse
}

// IsSuccess returns true when this get file payment consent file request o k response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get file payment consent file request o k response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request o k response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file payment consent file request o k response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request o k response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get file payment consent file request o k response
func (o *GetFilePaymentConsentFileRequestOK) Code() int {
	return 200
}

func (o *GetFilePaymentConsentFileRequestOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestOK %s", 200, payload)
}

func (o *GetFilePaymentConsentFileRequestOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestOK %s", 200, payload)
}

func (o *GetFilePaymentConsentFileRequestOK) GetPayload() models.FilePaymentConsentFileResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestBadRequest creates a GetFilePaymentConsentFileRequestBadRequest with default headers values
func NewGetFilePaymentConsentFileRequestBadRequest() *GetFilePaymentConsentFileRequestBadRequest {
	return &GetFilePaymentConsentFileRequestBadRequest{}
}

/*
GetFilePaymentConsentFileRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request bad request response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request bad request response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request bad request response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request bad request response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request bad request response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get file payment consent file request bad request response
func (o *GetFilePaymentConsentFileRequestBadRequest) Code() int {
	return 400
}

func (o *GetFilePaymentConsentFileRequestBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestBadRequest %s", 400, payload)
}

func (o *GetFilePaymentConsentFileRequestBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestBadRequest %s", 400, payload)
}

func (o *GetFilePaymentConsentFileRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestUnauthorized creates a GetFilePaymentConsentFileRequestUnauthorized with default headers values
func NewGetFilePaymentConsentFileRequestUnauthorized() *GetFilePaymentConsentFileRequestUnauthorized {
	return &GetFilePaymentConsentFileRequestUnauthorized{}
}

/*
GetFilePaymentConsentFileRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request unauthorized response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request unauthorized response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request unauthorized response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request unauthorized response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request unauthorized response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get file payment consent file request unauthorized response
func (o *GetFilePaymentConsentFileRequestUnauthorized) Code() int {
	return 401
}

func (o *GetFilePaymentConsentFileRequestUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestUnauthorized %s", 401, payload)
}

func (o *GetFilePaymentConsentFileRequestUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestUnauthorized %s", 401, payload)
}

func (o *GetFilePaymentConsentFileRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestForbidden creates a GetFilePaymentConsentFileRequestForbidden with default headers values
func NewGetFilePaymentConsentFileRequestForbidden() *GetFilePaymentConsentFileRequestForbidden {
	return &GetFilePaymentConsentFileRequestForbidden{}
}

/*
GetFilePaymentConsentFileRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request forbidden response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request forbidden response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request forbidden response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request forbidden response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request forbidden response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get file payment consent file request forbidden response
func (o *GetFilePaymentConsentFileRequestForbidden) Code() int {
	return 403
}

func (o *GetFilePaymentConsentFileRequestForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestForbidden %s", 403, payload)
}

func (o *GetFilePaymentConsentFileRequestForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestForbidden %s", 403, payload)
}

func (o *GetFilePaymentConsentFileRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestMethodNotAllowed creates a GetFilePaymentConsentFileRequestMethodNotAllowed with default headers values
func NewGetFilePaymentConsentFileRequestMethodNotAllowed() *GetFilePaymentConsentFileRequestMethodNotAllowed {
	return &GetFilePaymentConsentFileRequestMethodNotAllowed{}
}

/*
GetFilePaymentConsentFileRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request method not allowed response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request method not allowed response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request method not allowed response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request method not allowed response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request method not allowed response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get file payment consent file request method not allowed response
func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) Code() int {
	return 405
}

func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestMethodNotAllowed %s", 405, payload)
}

func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestMethodNotAllowed %s", 405, payload)
}

func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestNotAcceptable creates a GetFilePaymentConsentFileRequestNotAcceptable with default headers values
func NewGetFilePaymentConsentFileRequestNotAcceptable() *GetFilePaymentConsentFileRequestNotAcceptable {
	return &GetFilePaymentConsentFileRequestNotAcceptable{}
}

/*
GetFilePaymentConsentFileRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request not acceptable response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request not acceptable response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request not acceptable response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request not acceptable response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request not acceptable response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get file payment consent file request not acceptable response
func (o *GetFilePaymentConsentFileRequestNotAcceptable) Code() int {
	return 406
}

func (o *GetFilePaymentConsentFileRequestNotAcceptable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestNotAcceptable %s", 406, payload)
}

func (o *GetFilePaymentConsentFileRequestNotAcceptable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestNotAcceptable %s", 406, payload)
}

func (o *GetFilePaymentConsentFileRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestUnsupportedMediaType creates a GetFilePaymentConsentFileRequestUnsupportedMediaType with default headers values
func NewGetFilePaymentConsentFileRequestUnsupportedMediaType() *GetFilePaymentConsentFileRequestUnsupportedMediaType {
	return &GetFilePaymentConsentFileRequestUnsupportedMediaType{}
}

/*
GetFilePaymentConsentFileRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request unsupported media type response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request unsupported media type response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request unsupported media type response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request unsupported media type response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request unsupported media type response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get file payment consent file request unsupported media type response
func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestUnsupportedMediaType %s", 415, payload)
}

func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestUnsupportedMediaType %s", 415, payload)
}

func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestTooManyRequests creates a GetFilePaymentConsentFileRequestTooManyRequests with default headers values
func NewGetFilePaymentConsentFileRequestTooManyRequests() *GetFilePaymentConsentFileRequestTooManyRequests {
	return &GetFilePaymentConsentFileRequestTooManyRequests{}
}

/*
GetFilePaymentConsentFileRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request too many requests response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request too many requests response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request too many requests response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consent file request too many requests response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consent file request too many requests response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get file payment consent file request too many requests response
func (o *GetFilePaymentConsentFileRequestTooManyRequests) Code() int {
	return 429
}

func (o *GetFilePaymentConsentFileRequestTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestTooManyRequests %s", 429, payload)
}

func (o *GetFilePaymentConsentFileRequestTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestTooManyRequests %s", 429, payload)
}

func (o *GetFilePaymentConsentFileRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetFilePaymentConsentFileRequestInternalServerError creates a GetFilePaymentConsentFileRequestInternalServerError with default headers values
func NewGetFilePaymentConsentFileRequestInternalServerError() *GetFilePaymentConsentFileRequestInternalServerError {
	return &GetFilePaymentConsentFileRequestInternalServerError{}
}

/*
GetFilePaymentConsentFileRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetFilePaymentConsentFileRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get file payment consent file request internal server error response has a 2xx status code
func (o *GetFilePaymentConsentFileRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consent file request internal server error response has a 3xx status code
func (o *GetFilePaymentConsentFileRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consent file request internal server error response has a 4xx status code
func (o *GetFilePaymentConsentFileRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file payment consent file request internal server error response has a 5xx status code
func (o *GetFilePaymentConsentFileRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get file payment consent file request internal server error response a status code equal to that given
func (o *GetFilePaymentConsentFileRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get file payment consent file request internal server error response
func (o *GetFilePaymentConsentFileRequestInternalServerError) Code() int {
	return 500
}

func (o *GetFilePaymentConsentFileRequestInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestInternalServerError %s", 500, payload)
}

func (o *GetFilePaymentConsentFileRequestInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/v3.1/pisp/file-payment-consents/{consentID}/file][%d] getFilePaymentConsentFileRequestInternalServerError %s", 500, payload)
}

func (o *GetFilePaymentConsentFileRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetFilePaymentConsentFileRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
