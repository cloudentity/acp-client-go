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

// GetDataAccessConsentV2Reader is a Reader for the GetDataAccessConsentV2 structure.
type GetDataAccessConsentV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDataAccessConsentV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDataAccessConsentV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDataAccessConsentV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetDataAccessConsentV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDataAccessConsentV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetDataAccessConsentV2MethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetDataAccessConsentV2NotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewGetDataAccessConsentV2UnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGetDataAccessConsentV2UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDataAccessConsentV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDataAccessConsentV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/consents/v2/consents/{consentID}] GetDataAccessConsentV2", response, response.Code())
	}
}

// NewGetDataAccessConsentV2OK creates a GetDataAccessConsentV2OK with default headers values
func NewGetDataAccessConsentV2OK() *GetDataAccessConsentV2OK {
	return &GetDataAccessConsentV2OK{}
}

/*
GetDataAccessConsentV2OK describes a response with status code 200, with default header values.

Get Customer data access v2 consent
*/
type GetDataAccessConsentV2OK struct {
	Payload *models.BrazilGetCustomerDataAccessConsentV2Response
}

// IsSuccess returns true when this get data access consent v2 o k response has a 2xx status code
func (o *GetDataAccessConsentV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get data access consent v2 o k response has a 3xx status code
func (o *GetDataAccessConsentV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 o k response has a 4xx status code
func (o *GetDataAccessConsentV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get data access consent v2 o k response has a 5xx status code
func (o *GetDataAccessConsentV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 o k response a status code equal to that given
func (o *GetDataAccessConsentV2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get data access consent v2 o k response
func (o *GetDataAccessConsentV2OK) Code() int {
	return 200
}

func (o *GetDataAccessConsentV2OK) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2OK  %+v", 200, o.Payload)
}

func (o *GetDataAccessConsentV2OK) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2OK  %+v", 200, o.Payload)
}

func (o *GetDataAccessConsentV2OK) GetPayload() *models.BrazilGetCustomerDataAccessConsentV2Response {
	return o.Payload
}

func (o *GetDataAccessConsentV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilGetCustomerDataAccessConsentV2Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2BadRequest creates a GetDataAccessConsentV2BadRequest with default headers values
func NewGetDataAccessConsentV2BadRequest() *GetDataAccessConsentV2BadRequest {
	return &GetDataAccessConsentV2BadRequest{}
}

/*
GetDataAccessConsentV2BadRequest describes a response with status code 400, with default header values.

Error
*/
type GetDataAccessConsentV2BadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 bad request response has a 2xx status code
func (o *GetDataAccessConsentV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 bad request response has a 3xx status code
func (o *GetDataAccessConsentV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 bad request response has a 4xx status code
func (o *GetDataAccessConsentV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 bad request response has a 5xx status code
func (o *GetDataAccessConsentV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 bad request response a status code equal to that given
func (o *GetDataAccessConsentV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get data access consent v2 bad request response
func (o *GetDataAccessConsentV2BadRequest) Code() int {
	return 400
}

func (o *GetDataAccessConsentV2BadRequest) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetDataAccessConsentV2BadRequest) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2BadRequest  %+v", 400, o.Payload)
}

func (o *GetDataAccessConsentV2BadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2Unauthorized creates a GetDataAccessConsentV2Unauthorized with default headers values
func NewGetDataAccessConsentV2Unauthorized() *GetDataAccessConsentV2Unauthorized {
	return &GetDataAccessConsentV2Unauthorized{}
}

/*
GetDataAccessConsentV2Unauthorized describes a response with status code 401, with default header values.

Error
*/
type GetDataAccessConsentV2Unauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 unauthorized response has a 2xx status code
func (o *GetDataAccessConsentV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 unauthorized response has a 3xx status code
func (o *GetDataAccessConsentV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 unauthorized response has a 4xx status code
func (o *GetDataAccessConsentV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 unauthorized response has a 5xx status code
func (o *GetDataAccessConsentV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 unauthorized response a status code equal to that given
func (o *GetDataAccessConsentV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get data access consent v2 unauthorized response
func (o *GetDataAccessConsentV2Unauthorized) Code() int {
	return 401
}

func (o *GetDataAccessConsentV2Unauthorized) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetDataAccessConsentV2Unauthorized) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2Unauthorized  %+v", 401, o.Payload)
}

func (o *GetDataAccessConsentV2Unauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2Forbidden creates a GetDataAccessConsentV2Forbidden with default headers values
func NewGetDataAccessConsentV2Forbidden() *GetDataAccessConsentV2Forbidden {
	return &GetDataAccessConsentV2Forbidden{}
}

/*
GetDataAccessConsentV2Forbidden describes a response with status code 403, with default header values.

Error
*/
type GetDataAccessConsentV2Forbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 forbidden response has a 2xx status code
func (o *GetDataAccessConsentV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 forbidden response has a 3xx status code
func (o *GetDataAccessConsentV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 forbidden response has a 4xx status code
func (o *GetDataAccessConsentV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 forbidden response has a 5xx status code
func (o *GetDataAccessConsentV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 forbidden response a status code equal to that given
func (o *GetDataAccessConsentV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get data access consent v2 forbidden response
func (o *GetDataAccessConsentV2Forbidden) Code() int {
	return 403
}

func (o *GetDataAccessConsentV2Forbidden) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetDataAccessConsentV2Forbidden) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2Forbidden  %+v", 403, o.Payload)
}

func (o *GetDataAccessConsentV2Forbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2MethodNotAllowed creates a GetDataAccessConsentV2MethodNotAllowed with default headers values
func NewGetDataAccessConsentV2MethodNotAllowed() *GetDataAccessConsentV2MethodNotAllowed {
	return &GetDataAccessConsentV2MethodNotAllowed{}
}

/*
GetDataAccessConsentV2MethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type GetDataAccessConsentV2MethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 method not allowed response has a 2xx status code
func (o *GetDataAccessConsentV2MethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 method not allowed response has a 3xx status code
func (o *GetDataAccessConsentV2MethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 method not allowed response has a 4xx status code
func (o *GetDataAccessConsentV2MethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 method not allowed response has a 5xx status code
func (o *GetDataAccessConsentV2MethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 method not allowed response a status code equal to that given
func (o *GetDataAccessConsentV2MethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get data access consent v2 method not allowed response
func (o *GetDataAccessConsentV2MethodNotAllowed) Code() int {
	return 405
}

func (o *GetDataAccessConsentV2MethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetDataAccessConsentV2MethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *GetDataAccessConsentV2MethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2MethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2NotAcceptable creates a GetDataAccessConsentV2NotAcceptable with default headers values
func NewGetDataAccessConsentV2NotAcceptable() *GetDataAccessConsentV2NotAcceptable {
	return &GetDataAccessConsentV2NotAcceptable{}
}

/*
GetDataAccessConsentV2NotAcceptable describes a response with status code 406, with default header values.

Error
*/
type GetDataAccessConsentV2NotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 not acceptable response has a 2xx status code
func (o *GetDataAccessConsentV2NotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 not acceptable response has a 3xx status code
func (o *GetDataAccessConsentV2NotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 not acceptable response has a 4xx status code
func (o *GetDataAccessConsentV2NotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 not acceptable response has a 5xx status code
func (o *GetDataAccessConsentV2NotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 not acceptable response a status code equal to that given
func (o *GetDataAccessConsentV2NotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get data access consent v2 not acceptable response
func (o *GetDataAccessConsentV2NotAcceptable) Code() int {
	return 406
}

func (o *GetDataAccessConsentV2NotAcceptable) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2NotAcceptable  %+v", 406, o.Payload)
}

func (o *GetDataAccessConsentV2NotAcceptable) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2NotAcceptable  %+v", 406, o.Payload)
}

func (o *GetDataAccessConsentV2NotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2NotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2UnsupportedMediaType creates a GetDataAccessConsentV2UnsupportedMediaType with default headers values
func NewGetDataAccessConsentV2UnsupportedMediaType() *GetDataAccessConsentV2UnsupportedMediaType {
	return &GetDataAccessConsentV2UnsupportedMediaType{}
}

/*
GetDataAccessConsentV2UnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type GetDataAccessConsentV2UnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 unsupported media type response has a 2xx status code
func (o *GetDataAccessConsentV2UnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 unsupported media type response has a 3xx status code
func (o *GetDataAccessConsentV2UnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 unsupported media type response has a 4xx status code
func (o *GetDataAccessConsentV2UnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 unsupported media type response has a 5xx status code
func (o *GetDataAccessConsentV2UnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 unsupported media type response a status code equal to that given
func (o *GetDataAccessConsentV2UnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the get data access consent v2 unsupported media type response
func (o *GetDataAccessConsentV2UnsupportedMediaType) Code() int {
	return 415
}

func (o *GetDataAccessConsentV2UnsupportedMediaType) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetDataAccessConsentV2UnsupportedMediaType) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *GetDataAccessConsentV2UnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2UnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2UnprocessableEntity creates a GetDataAccessConsentV2UnprocessableEntity with default headers values
func NewGetDataAccessConsentV2UnprocessableEntity() *GetDataAccessConsentV2UnprocessableEntity {
	return &GetDataAccessConsentV2UnprocessableEntity{}
}

/*
GetDataAccessConsentV2UnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type GetDataAccessConsentV2UnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 unprocessable entity response has a 2xx status code
func (o *GetDataAccessConsentV2UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 unprocessable entity response has a 3xx status code
func (o *GetDataAccessConsentV2UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 unprocessable entity response has a 4xx status code
func (o *GetDataAccessConsentV2UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 unprocessable entity response has a 5xx status code
func (o *GetDataAccessConsentV2UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 unprocessable entity response a status code equal to that given
func (o *GetDataAccessConsentV2UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the get data access consent v2 unprocessable entity response
func (o *GetDataAccessConsentV2UnprocessableEntity) Code() int {
	return 422
}

func (o *GetDataAccessConsentV2UnprocessableEntity) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetDataAccessConsentV2UnprocessableEntity) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GetDataAccessConsentV2UnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2TooManyRequests creates a GetDataAccessConsentV2TooManyRequests with default headers values
func NewGetDataAccessConsentV2TooManyRequests() *GetDataAccessConsentV2TooManyRequests {
	return &GetDataAccessConsentV2TooManyRequests{}
}

/*
GetDataAccessConsentV2TooManyRequests describes a response with status code 429, with default header values.

Error
*/
type GetDataAccessConsentV2TooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 too many requests response has a 2xx status code
func (o *GetDataAccessConsentV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 too many requests response has a 3xx status code
func (o *GetDataAccessConsentV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 too many requests response has a 4xx status code
func (o *GetDataAccessConsentV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get data access consent v2 too many requests response has a 5xx status code
func (o *GetDataAccessConsentV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get data access consent v2 too many requests response a status code equal to that given
func (o *GetDataAccessConsentV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get data access consent v2 too many requests response
func (o *GetDataAccessConsentV2TooManyRequests) Code() int {
	return 429
}

func (o *GetDataAccessConsentV2TooManyRequests) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDataAccessConsentV2TooManyRequests) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *GetDataAccessConsentV2TooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDataAccessConsentV2InternalServerError creates a GetDataAccessConsentV2InternalServerError with default headers values
func NewGetDataAccessConsentV2InternalServerError() *GetDataAccessConsentV2InternalServerError {
	return &GetDataAccessConsentV2InternalServerError{}
}

/*
GetDataAccessConsentV2InternalServerError describes a response with status code 500, with default header values.

Error
*/
type GetDataAccessConsentV2InternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this get data access consent v2 internal server error response has a 2xx status code
func (o *GetDataAccessConsentV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get data access consent v2 internal server error response has a 3xx status code
func (o *GetDataAccessConsentV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get data access consent v2 internal server error response has a 4xx status code
func (o *GetDataAccessConsentV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get data access consent v2 internal server error response has a 5xx status code
func (o *GetDataAccessConsentV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get data access consent v2 internal server error response a status code equal to that given
func (o *GetDataAccessConsentV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get data access consent v2 internal server error response
func (o *GetDataAccessConsentV2InternalServerError) Code() int {
	return 500
}

func (o *GetDataAccessConsentV2InternalServerError) Error() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2InternalServerError  %+v", 500, o.Payload)
}

func (o *GetDataAccessConsentV2InternalServerError) String() string {
	return fmt.Sprintf("[GET /open-banking/consents/v2/consents/{consentID}][%d] getDataAccessConsentV2InternalServerError  %+v", 500, o.Payload)
}

func (o *GetDataAccessConsentV2InternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *GetDataAccessConsentV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}