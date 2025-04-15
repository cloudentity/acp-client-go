// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// GetDataAccessConsentReader is a Reader for the GetDataAccessConsent structure.
type GetDataAccessConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDataAccessConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDataAccessConsentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDataAccessConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetDataAccessConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDataAccessConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetDataAccessConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetDataAccessConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetDataAccessConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetDataAccessConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDataAccessConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDataAccessConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/consents/v1/consents/{consentID}] GetDataAccessConsent", response, response.Code())
	}
}

// NewGetDataAccessConsentOK creates a GetDataAccessConsentOK with default headers values
func NewGetDataAccessConsentOK() *GetDataAccessConsentOK {
	return &GetDataAccessConsentOK{}
}

/*
GetDataAccessConsentOK describes a response with status code 200, with default header values.

Customer data access consent
*/
type GetDataAccessConsentOK struct {
	Payload *models.BrazilCustomerDataAccessConsentResponse
}

// IsSuccess returns true when this get data access consent o k response has a 2xx status code
func (o *GetDataAccessConsentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get data access consent o k response has a 3xx status code
func (o *GetDataAccessConsentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent o k response has a 4xx status code
func (o *GetDataAccessConsentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get data access consent o k response has a 5xx status code
func (o *GetDataAccessConsentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent o k response a status code equal to that given
func (o *GetDataAccessConsentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get data access consent o k response
func (o *GetDataAccessConsentOK) Code() int {
	return 200
}

func (o *GetDataAccessConsentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentOK %s", 200, payload)
}

func (o *GetDataAccessConsentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentOK %s", 200, payload)
}

func (o *GetDataAccessConsentOK) GetPayload() *models.BrazilCustomerDataAccessConsentResponse {
	return o.Payload
}

func (o *GetDataAccessConsentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerDataAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentBadRequest creates a GetDataAccessConsentBadRequest with default headers values
func NewGetDataAccessConsentBadRequest() *GetDataAccessConsentBadRequest {
	return &GetDataAccessConsentBadRequest{}
}

/*
GetDataAccessConsentBadRequest describes a response with status code 400, with default header values.

Error
*/
type GetDataAccessConsentBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent bad request response has a 2xx status code
func (o *GetDataAccessConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent bad request response has a 3xx status code
func (o *GetDataAccessConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent bad request response has a 4xx status code
func (o *GetDataAccessConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent bad request response has a 5xx status code
func (o *GetDataAccessConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent bad request response a status code equal to that given
func (o *GetDataAccessConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get data access consent bad request response
func (o *GetDataAccessConsentBadRequest) Code() int {
	return 400
}

func (o *GetDataAccessConsentBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentBadRequest %s", 400, payload)
}

func (o *GetDataAccessConsentBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentBadRequest %s", 400, payload)
}

func (o *GetDataAccessConsentBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentUnauthorized creates a GetDataAccessConsentUnauthorized with default headers values
func NewGetDataAccessConsentUnauthorized() *GetDataAccessConsentUnauthorized {
	return &GetDataAccessConsentUnauthorized{}
}

/*
GetDataAccessConsentUnauthorized describes a response with status code 401, with default header values.

Error
*/
type GetDataAccessConsentUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent unauthorized response has a 2xx status code
func (o *GetDataAccessConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent unauthorized response has a 3xx status code
func (o *GetDataAccessConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent unauthorized response has a 4xx status code
func (o *GetDataAccessConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent unauthorized response has a 5xx status code
func (o *GetDataAccessConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent unauthorized response a status code equal to that given
func (o *GetDataAccessConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get data access consent unauthorized response
func (o *GetDataAccessConsentUnauthorized) Code() int {
	return 401
}

func (o *GetDataAccessConsentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnauthorized %s", 401, payload)
}

func (o *GetDataAccessConsentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnauthorized %s", 401, payload)
}

func (o *GetDataAccessConsentUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentForbidden creates a GetDataAccessConsentForbidden with default headers values
func NewGetDataAccessConsentForbidden() *GetDataAccessConsentForbidden {
	return &GetDataAccessConsentForbidden{}
}

/*
GetDataAccessConsentForbidden describes a response with status code 403, with default header values.

Error
*/
type GetDataAccessConsentForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent forbidden response has a 2xx status code
func (o *GetDataAccessConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent forbidden response has a 3xx status code
func (o *GetDataAccessConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent forbidden response has a 4xx status code
func (o *GetDataAccessConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent forbidden response has a 5xx status code
func (o *GetDataAccessConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent forbidden response a status code equal to that given
func (o *GetDataAccessConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get data access consent forbidden response
func (o *GetDataAccessConsentForbidden) Code() int {
	return 403
}

func (o *GetDataAccessConsentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentForbidden %s", 403, payload)
}

func (o *GetDataAccessConsentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentForbidden %s", 403, payload)
}

func (o *GetDataAccessConsentForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentMethodNotAllowed creates a GetDataAccessConsentMethodNotAllowed with default headers values
func NewGetDataAccessConsentMethodNotAllowed() *GetDataAccessConsentMethodNotAllowed {
	return &GetDataAccessConsentMethodNotAllowed{}
}

/*
GetDataAccessConsentMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetDataAccessConsentMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent method not allowed response has a 2xx status code
func (o *GetDataAccessConsentMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent method not allowed response has a 3xx status code
func (o *GetDataAccessConsentMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent method not allowed response has a 4xx status code
func (o *GetDataAccessConsentMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent method not allowed response has a 5xx status code
func (o *GetDataAccessConsentMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent method not allowed response a status code equal to that given
func (o *GetDataAccessConsentMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get data access consent method not allowed response
func (o *GetDataAccessConsentMethodNotAllowed) Code() int {
	return 405
}

func (o *GetDataAccessConsentMethodNotAllowed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentMethodNotAllowed %s", 405, payload)
}

func (o *GetDataAccessConsentMethodNotAllowed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentMethodNotAllowed %s", 405, payload)
}

func (o *GetDataAccessConsentMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentNotAcceptable creates a GetDataAccessConsentNotAcceptable with default headers values
func NewGetDataAccessConsentNotAcceptable() *GetDataAccessConsentNotAcceptable {
	return &GetDataAccessConsentNotAcceptable{}
}

/*
GetDataAccessConsentNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetDataAccessConsentNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent not acceptable response has a 2xx status code
func (o *GetDataAccessConsentNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent not acceptable response has a 3xx status code
func (o *GetDataAccessConsentNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent not acceptable response has a 4xx status code
func (o *GetDataAccessConsentNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent not acceptable response has a 5xx status code
func (o *GetDataAccessConsentNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent not acceptable response a status code equal to that given
func (o *GetDataAccessConsentNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get data access consent not acceptable response
func (o *GetDataAccessConsentNotAcceptable) Code() int {
	return 406
}

func (o *GetDataAccessConsentNotAcceptable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentNotAcceptable %s", 406, payload)
}

func (o *GetDataAccessConsentNotAcceptable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentNotAcceptable %s", 406, payload)
}

func (o *GetDataAccessConsentNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentUnsupportedMediaType creates a GetDataAccessConsentUnsupportedMediaType with default headers values
func NewGetDataAccessConsentUnsupportedMediaType() *GetDataAccessConsentUnsupportedMediaType {
	return &GetDataAccessConsentUnsupportedMediaType{}
}

/*
GetDataAccessConsentUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetDataAccessConsentUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent unsupported media type response has a 2xx status code
func (o *GetDataAccessConsentUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent unsupported media type response has a 3xx status code
func (o *GetDataAccessConsentUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent unsupported media type response has a 4xx status code
func (o *GetDataAccessConsentUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent unsupported media type response has a 5xx status code
func (o *GetDataAccessConsentUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent unsupported media type response a status code equal to that given
func (o *GetDataAccessConsentUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get data access consent unsupported media type response
func (o *GetDataAccessConsentUnsupportedMediaType) Code() int {
	return 415
}

func (o *GetDataAccessConsentUnsupportedMediaType) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnsupportedMediaType %s", 415, payload)
}

func (o *GetDataAccessConsentUnsupportedMediaType) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnsupportedMediaType %s", 415, payload)
}

func (o *GetDataAccessConsentUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentUnprocessableEntity creates a GetDataAccessConsentUnprocessableEntity with default headers values
func NewGetDataAccessConsentUnprocessableEntity() *GetDataAccessConsentUnprocessableEntity {
	return &GetDataAccessConsentUnprocessableEntity{}
}

/*
GetDataAccessConsentUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type GetDataAccessConsentUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent unprocessable entity response has a 2xx status code
func (o *GetDataAccessConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent unprocessable entity response has a 3xx status code
func (o *GetDataAccessConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent unprocessable entity response has a 4xx status code
func (o *GetDataAccessConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent unprocessable entity response has a 5xx status code
func (o *GetDataAccessConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent unprocessable entity response a status code equal to that given
func (o *GetDataAccessConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the get data access consent unprocessable entity response
func (o *GetDataAccessConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *GetDataAccessConsentUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnprocessableEntity %s", 422, payload)
}

func (o *GetDataAccessConsentUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentUnprocessableEntity %s", 422, payload)
}

func (o *GetDataAccessConsentUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentTooManyRequests creates a GetDataAccessConsentTooManyRequests with default headers values
func NewGetDataAccessConsentTooManyRequests() *GetDataAccessConsentTooManyRequests {
	return &GetDataAccessConsentTooManyRequests{}
}

/*
GetDataAccessConsentTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetDataAccessConsentTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent too many requests response has a 2xx status code
func (o *GetDataAccessConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent too many requests response has a 3xx status code
func (o *GetDataAccessConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent too many requests response has a 4xx status code
func (o *GetDataAccessConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent too many requests response has a 5xx status code
func (o *GetDataAccessConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent too many requests response a status code equal to that given
func (o *GetDataAccessConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get data access consent too many requests response
func (o *GetDataAccessConsentTooManyRequests) Code() int {
	return 429
}

func (o *GetDataAccessConsentTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentTooManyRequests %s", 429, payload)
}

func (o *GetDataAccessConsentTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentTooManyRequests %s", 429, payload)
}

func (o *GetDataAccessConsentTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentInternalServerError creates a GetDataAccessConsentInternalServerError with default headers values
func NewGetDataAccessConsentInternalServerError() *GetDataAccessConsentInternalServerError {
	return &GetDataAccessConsentInternalServerError{}
}

/*
GetDataAccessConsentInternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetDataAccessConsentInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent internal server error response has a 2xx status code
func (o *GetDataAccessConsentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent internal server error response has a 3xx status code
func (o *GetDataAccessConsentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent internal server error response has a 4xx status code
func (o *GetDataAccessConsentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get data access consent internal server error response has a 5xx status code
func (o *GetDataAccessConsentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get data access consent internal server error response a status code equal to that given
func (o *GetDataAccessConsentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get data access consent internal server error response
func (o *GetDataAccessConsentInternalServerError) Code() int {
	return 500
}

func (o *GetDataAccessConsentInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentInternalServerError %s", 500, payload)
}

func (o *GetDataAccessConsentInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/consents/v1/consents/{consentID}][%d] getDataAccessConsentInternalServerError %s", 500, payload)
}

func (o *GetDataAccessConsentInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
