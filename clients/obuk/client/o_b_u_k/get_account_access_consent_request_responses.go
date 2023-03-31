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

// GetAccountAccessConsentRequestReader is a Reader for the GetAccountAccessConsentRequest structure.
type GetAccountAccessConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAccountAccessConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAccountAccessConsentRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAccountAccessConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAccountAccessConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAccountAccessConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetAccountAccessConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetAccountAccessConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetAccountAccessConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAccountAccessConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAccountAccessConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetAccountAccessConsentRequestOK creates a GetAccountAccessConsentRequestOK with default headers values
func NewGetAccountAccessConsentRequestOK() *GetAccountAccessConsentRequestOK {
	return &GetAccountAccessConsentRequestOK{}
}

/*
GetAccountAccessConsentRequestOK describes a response with status code 200, with default header values.

Account access consent
*/
type GetAccountAccessConsentRequestOK struct {
	Payload *models.AccountAccessConsentResponse
}

// IsSuccess returns true when this get account access consent request o k response has a 2xx status code
func (o *GetAccountAccessConsentRequestOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get account access consent request o k response has a 3xx status code
func (o *GetAccountAccessConsentRequestOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request o k response has a 4xx status code
func (o *GetAccountAccessConsentRequestOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get account access consent request o k response has a 5xx status code
func (o *GetAccountAccessConsentRequestOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request o k response a status code equal to that given
func (o *GetAccountAccessConsentRequestOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get account access consent request o k response
func (o *GetAccountAccessConsentRequestOK) Code() int {
	return 200
}

func (o *GetAccountAccessConsentRequestOK) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetAccountAccessConsentRequestOK) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestOK  %+v", 200, o.Payload)
}

func (o *GetAccountAccessConsentRequestOK) GetPayload() *models.AccountAccessConsentResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AccountAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestBadRequest creates a GetAccountAccessConsentRequestBadRequest with default headers values
func NewGetAccountAccessConsentRequestBadRequest() *GetAccountAccessConsentRequestBadRequest {
	return &GetAccountAccessConsentRequestBadRequest{}
}

/*
GetAccountAccessConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetAccountAccessConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request bad request response has a 2xx status code
func (o *GetAccountAccessConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request bad request response has a 3xx status code
func (o *GetAccountAccessConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request bad request response has a 4xx status code
func (o *GetAccountAccessConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request bad request response has a 5xx status code
func (o *GetAccountAccessConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request bad request response a status code equal to that given
func (o *GetAccountAccessConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get account access consent request bad request response
func (o *GetAccountAccessConsentRequestBadRequest) Code() int {
	return 400
}

func (o *GetAccountAccessConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetAccountAccessConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *GetAccountAccessConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestUnauthorized creates a GetAccountAccessConsentRequestUnauthorized with default headers values
func NewGetAccountAccessConsentRequestUnauthorized() *GetAccountAccessConsentRequestUnauthorized {
	return &GetAccountAccessConsentRequestUnauthorized{}
}

/*
GetAccountAccessConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetAccountAccessConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request unauthorized response has a 2xx status code
func (o *GetAccountAccessConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request unauthorized response has a 3xx status code
func (o *GetAccountAccessConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request unauthorized response has a 4xx status code
func (o *GetAccountAccessConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request unauthorized response has a 5xx status code
func (o *GetAccountAccessConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request unauthorized response a status code equal to that given
func (o *GetAccountAccessConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get account access consent request unauthorized response
func (o *GetAccountAccessConsentRequestUnauthorized) Code() int {
	return 401
}

func (o *GetAccountAccessConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAccountAccessConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAccountAccessConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestForbidden creates a GetAccountAccessConsentRequestForbidden with default headers values
func NewGetAccountAccessConsentRequestForbidden() *GetAccountAccessConsentRequestForbidden {
	return &GetAccountAccessConsentRequestForbidden{}
}

/*
GetAccountAccessConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type GetAccountAccessConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request forbidden response has a 2xx status code
func (o *GetAccountAccessConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request forbidden response has a 3xx status code
func (o *GetAccountAccessConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request forbidden response has a 4xx status code
func (o *GetAccountAccessConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request forbidden response has a 5xx status code
func (o *GetAccountAccessConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request forbidden response a status code equal to that given
func (o *GetAccountAccessConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get account access consent request forbidden response
func (o *GetAccountAccessConsentRequestForbidden) Code() int {
	return 403
}

func (o *GetAccountAccessConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetAccountAccessConsentRequestForbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *GetAccountAccessConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestMethodNotAllowed creates a GetAccountAccessConsentRequestMethodNotAllowed with default headers values
func NewGetAccountAccessConsentRequestMethodNotAllowed() *GetAccountAccessConsentRequestMethodNotAllowed {
	return &GetAccountAccessConsentRequestMethodNotAllowed{}
}

/*
GetAccountAccessConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetAccountAccessConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request method not allowed response has a 2xx status code
func (o *GetAccountAccessConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request method not allowed response has a 3xx status code
func (o *GetAccountAccessConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request method not allowed response has a 4xx status code
func (o *GetAccountAccessConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request method not allowed response has a 5xx status code
func (o *GetAccountAccessConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request method not allowed response a status code equal to that given
func (o *GetAccountAccessConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get account access consent request method not allowed response
func (o *GetAccountAccessConsentRequestMethodNotAllowed) Code() int {
	return 405
}

func (o *GetAccountAccessConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetAccountAccessConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetAccountAccessConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestNotAcceptable creates a GetAccountAccessConsentRequestNotAcceptable with default headers values
func NewGetAccountAccessConsentRequestNotAcceptable() *GetAccountAccessConsentRequestNotAcceptable {
	return &GetAccountAccessConsentRequestNotAcceptable{}
}

/*
GetAccountAccessConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetAccountAccessConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request not acceptable response has a 2xx status code
func (o *GetAccountAccessConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request not acceptable response has a 3xx status code
func (o *GetAccountAccessConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request not acceptable response has a 4xx status code
func (o *GetAccountAccessConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request not acceptable response has a 5xx status code
func (o *GetAccountAccessConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request not acceptable response a status code equal to that given
func (o *GetAccountAccessConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get account access consent request not acceptable response
func (o *GetAccountAccessConsentRequestNotAcceptable) Code() int {
	return 406
}

func (o *GetAccountAccessConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetAccountAccessConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *GetAccountAccessConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestUnsupportedMediaType creates a GetAccountAccessConsentRequestUnsupportedMediaType with default headers values
func NewGetAccountAccessConsentRequestUnsupportedMediaType() *GetAccountAccessConsentRequestUnsupportedMediaType {
	return &GetAccountAccessConsentRequestUnsupportedMediaType{}
}

/*
GetAccountAccessConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetAccountAccessConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request unsupported media type response has a 2xx status code
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request unsupported media type response has a 3xx status code
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request unsupported media type response has a 4xx status code
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request unsupported media type response has a 5xx status code
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request unsupported media type response a status code equal to that given
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get account access consent request unsupported media type response
func (o *GetAccountAccessConsentRequestUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetAccountAccessConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetAccountAccessConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetAccountAccessConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestTooManyRequests creates a GetAccountAccessConsentRequestTooManyRequests with default headers values
func NewGetAccountAccessConsentRequestTooManyRequests() *GetAccountAccessConsentRequestTooManyRequests {
	return &GetAccountAccessConsentRequestTooManyRequests{}
}

/*
GetAccountAccessConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetAccountAccessConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request too many requests response has a 2xx status code
func (o *GetAccountAccessConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request too many requests response has a 3xx status code
func (o *GetAccountAccessConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request too many requests response has a 4xx status code
func (o *GetAccountAccessConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consent request too many requests response has a 5xx status code
func (o *GetAccountAccessConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consent request too many requests response a status code equal to that given
func (o *GetAccountAccessConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get account access consent request too many requests response
func (o *GetAccountAccessConsentRequestTooManyRequests) Code() int {
	return 429
}

func (o *GetAccountAccessConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAccountAccessConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAccountAccessConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentRequestInternalServerError creates a GetAccountAccessConsentRequestInternalServerError with default headers values
func NewGetAccountAccessConsentRequestInternalServerError() *GetAccountAccessConsentRequestInternalServerError {
	return &GetAccountAccessConsentRequestInternalServerError{}
}

/*
GetAccountAccessConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetAccountAccessConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this get account access consent request internal server error response has a 2xx status code
func (o *GetAccountAccessConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consent request internal server error response has a 3xx status code
func (o *GetAccountAccessConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consent request internal server error response has a 4xx status code
func (o *GetAccountAccessConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get account access consent request internal server error response has a 5xx status code
func (o *GetAccountAccessConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get account access consent request internal server error response a status code equal to that given
func (o *GetAccountAccessConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get account access consent request internal server error response
func (o *GetAccountAccessConsentRequestInternalServerError) Code() int {
	return 500
}

func (o *GetAccountAccessConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetAccountAccessConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/v3.1/aisp/account-access-consents/{consentID}][%d] getAccountAccessConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetAccountAccessConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetAccountAccessConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
