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

// CreatePaymentConsentV3Reader is a Reader for the CreatePaymentConsentV3 structure.
type CreatePaymentConsentV3Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreatePaymentConsentV3Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreatePaymentConsentV3Created()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreatePaymentConsentV3BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreatePaymentConsentV3Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreatePaymentConsentV3Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreatePaymentConsentV3MethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreatePaymentConsentV3NotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreatePaymentConsentV3UnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreatePaymentConsentV3UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreatePaymentConsentV3TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreatePaymentConsentV3InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/payments/v3/consents] CreatePaymentConsentV3", response, response.Code())
	}
}

// NewCreatePaymentConsentV3Created creates a CreatePaymentConsentV3Created with default headers values
func NewCreatePaymentConsentV3Created() *CreatePaymentConsentV3Created {
	return &CreatePaymentConsentV3Created{}
}

/*
CreatePaymentConsentV3Created describes a response with status code 201, with default header values.

Customer payment consent
*/
type CreatePaymentConsentV3Created struct {
	Payload *models.BrazilCustomerPaymentConsentResponseV3
}

// IsSuccess returns true when this create payment consent v3 created response has a 2xx status code
func (o *CreatePaymentConsentV3Created) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create payment consent v3 created response has a 3xx status code
func (o *CreatePaymentConsentV3Created) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 created response has a 4xx status code
func (o *CreatePaymentConsentV3Created) IsClientError() bool {
	return false
}

// IsServerError returns true when this create payment consent v3 created response has a 5xx status code
func (o *CreatePaymentConsentV3Created) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 created response a status code equal to that given
func (o *CreatePaymentConsentV3Created) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create payment consent v3 created response
func (o *CreatePaymentConsentV3Created) Code() int {
	return 201
}

func (o *CreatePaymentConsentV3Created) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Created  %+v", 201, o.Payload)
}

func (o *CreatePaymentConsentV3Created) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Created  %+v", 201, o.Payload)
}

func (o *CreatePaymentConsentV3Created) GetPayload() *models.BrazilCustomerPaymentConsentResponseV3 {
	return o.Payload
}

func (o *CreatePaymentConsentV3Created) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerPaymentConsentResponseV3)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3BadRequest creates a CreatePaymentConsentV3BadRequest with default headers values
func NewCreatePaymentConsentV3BadRequest() *CreatePaymentConsentV3BadRequest {
	return &CreatePaymentConsentV3BadRequest{}
}

/*
CreatePaymentConsentV3BadRequest describes a response with status code 400, with default header values.

Error
*/
type CreatePaymentConsentV3BadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 bad request response has a 2xx status code
func (o *CreatePaymentConsentV3BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 bad request response has a 3xx status code
func (o *CreatePaymentConsentV3BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 bad request response has a 4xx status code
func (o *CreatePaymentConsentV3BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 bad request response has a 5xx status code
func (o *CreatePaymentConsentV3BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 bad request response a status code equal to that given
func (o *CreatePaymentConsentV3BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create payment consent v3 bad request response
func (o *CreatePaymentConsentV3BadRequest) Code() int {
	return 400
}

func (o *CreatePaymentConsentV3BadRequest) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3BadRequest  %+v", 400, o.Payload)
}

func (o *CreatePaymentConsentV3BadRequest) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3BadRequest  %+v", 400, o.Payload)
}

func (o *CreatePaymentConsentV3BadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3Unauthorized creates a CreatePaymentConsentV3Unauthorized with default headers values
func NewCreatePaymentConsentV3Unauthorized() *CreatePaymentConsentV3Unauthorized {
	return &CreatePaymentConsentV3Unauthorized{}
}

/*
CreatePaymentConsentV3Unauthorized describes a response with status code 401, with default header values.

Error
*/
type CreatePaymentConsentV3Unauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 unauthorized response has a 2xx status code
func (o *CreatePaymentConsentV3Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 unauthorized response has a 3xx status code
func (o *CreatePaymentConsentV3Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 unauthorized response has a 4xx status code
func (o *CreatePaymentConsentV3Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 unauthorized response has a 5xx status code
func (o *CreatePaymentConsentV3Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 unauthorized response a status code equal to that given
func (o *CreatePaymentConsentV3Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create payment consent v3 unauthorized response
func (o *CreatePaymentConsentV3Unauthorized) Code() int {
	return 401
}

func (o *CreatePaymentConsentV3Unauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Unauthorized  %+v", 401, o.Payload)
}

func (o *CreatePaymentConsentV3Unauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Unauthorized  %+v", 401, o.Payload)
}

func (o *CreatePaymentConsentV3Unauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3Forbidden creates a CreatePaymentConsentV3Forbidden with default headers values
func NewCreatePaymentConsentV3Forbidden() *CreatePaymentConsentV3Forbidden {
	return &CreatePaymentConsentV3Forbidden{}
}

/*
CreatePaymentConsentV3Forbidden describes a response with status code 403, with default header values.

Error
*/
type CreatePaymentConsentV3Forbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 forbidden response has a 2xx status code
func (o *CreatePaymentConsentV3Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 forbidden response has a 3xx status code
func (o *CreatePaymentConsentV3Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 forbidden response has a 4xx status code
func (o *CreatePaymentConsentV3Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 forbidden response has a 5xx status code
func (o *CreatePaymentConsentV3Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 forbidden response a status code equal to that given
func (o *CreatePaymentConsentV3Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create payment consent v3 forbidden response
func (o *CreatePaymentConsentV3Forbidden) Code() int {
	return 403
}

func (o *CreatePaymentConsentV3Forbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Forbidden  %+v", 403, o.Payload)
}

func (o *CreatePaymentConsentV3Forbidden) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3Forbidden  %+v", 403, o.Payload)
}

func (o *CreatePaymentConsentV3Forbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3MethodNotAllowed creates a CreatePaymentConsentV3MethodNotAllowed with default headers values
func NewCreatePaymentConsentV3MethodNotAllowed() *CreatePaymentConsentV3MethodNotAllowed {
	return &CreatePaymentConsentV3MethodNotAllowed{}
}

/*
CreatePaymentConsentV3MethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreatePaymentConsentV3MethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 method not allowed response has a 2xx status code
func (o *CreatePaymentConsentV3MethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 method not allowed response has a 3xx status code
func (o *CreatePaymentConsentV3MethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 method not allowed response has a 4xx status code
func (o *CreatePaymentConsentV3MethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 method not allowed response has a 5xx status code
func (o *CreatePaymentConsentV3MethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 method not allowed response a status code equal to that given
func (o *CreatePaymentConsentV3MethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create payment consent v3 method not allowed response
func (o *CreatePaymentConsentV3MethodNotAllowed) Code() int {
	return 405
}

func (o *CreatePaymentConsentV3MethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreatePaymentConsentV3MethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreatePaymentConsentV3MethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3MethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3NotAcceptable creates a CreatePaymentConsentV3NotAcceptable with default headers values
func NewCreatePaymentConsentV3NotAcceptable() *CreatePaymentConsentV3NotAcceptable {
	return &CreatePaymentConsentV3NotAcceptable{}
}

/*
CreatePaymentConsentV3NotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreatePaymentConsentV3NotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 not acceptable response has a 2xx status code
func (o *CreatePaymentConsentV3NotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 not acceptable response has a 3xx status code
func (o *CreatePaymentConsentV3NotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 not acceptable response has a 4xx status code
func (o *CreatePaymentConsentV3NotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 not acceptable response has a 5xx status code
func (o *CreatePaymentConsentV3NotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 not acceptable response a status code equal to that given
func (o *CreatePaymentConsentV3NotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create payment consent v3 not acceptable response
func (o *CreatePaymentConsentV3NotAcceptable) Code() int {
	return 406
}

func (o *CreatePaymentConsentV3NotAcceptable) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3NotAcceptable  %+v", 406, o.Payload)
}

func (o *CreatePaymentConsentV3NotAcceptable) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3NotAcceptable  %+v", 406, o.Payload)
}

func (o *CreatePaymentConsentV3NotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3NotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3UnsupportedMediaType creates a CreatePaymentConsentV3UnsupportedMediaType with default headers values
func NewCreatePaymentConsentV3UnsupportedMediaType() *CreatePaymentConsentV3UnsupportedMediaType {
	return &CreatePaymentConsentV3UnsupportedMediaType{}
}

/*
CreatePaymentConsentV3UnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreatePaymentConsentV3UnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 unsupported media type response has a 2xx status code
func (o *CreatePaymentConsentV3UnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 unsupported media type response has a 3xx status code
func (o *CreatePaymentConsentV3UnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 unsupported media type response has a 4xx status code
func (o *CreatePaymentConsentV3UnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 unsupported media type response has a 5xx status code
func (o *CreatePaymentConsentV3UnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 unsupported media type response a status code equal to that given
func (o *CreatePaymentConsentV3UnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create payment consent v3 unsupported media type response
func (o *CreatePaymentConsentV3UnsupportedMediaType) Code() int {
	return 415
}

func (o *CreatePaymentConsentV3UnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreatePaymentConsentV3UnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreatePaymentConsentV3UnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3UnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3UnprocessableEntity creates a CreatePaymentConsentV3UnprocessableEntity with default headers values
func NewCreatePaymentConsentV3UnprocessableEntity() *CreatePaymentConsentV3UnprocessableEntity {
	return &CreatePaymentConsentV3UnprocessableEntity{}
}

/*
CreatePaymentConsentV3UnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type CreatePaymentConsentV3UnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 unprocessable entity response has a 2xx status code
func (o *CreatePaymentConsentV3UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 unprocessable entity response has a 3xx status code
func (o *CreatePaymentConsentV3UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 unprocessable entity response has a 4xx status code
func (o *CreatePaymentConsentV3UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 unprocessable entity response has a 5xx status code
func (o *CreatePaymentConsentV3UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 unprocessable entity response a status code equal to that given
func (o *CreatePaymentConsentV3UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create payment consent v3 unprocessable entity response
func (o *CreatePaymentConsentV3UnprocessableEntity) Code() int {
	return 422
}

func (o *CreatePaymentConsentV3UnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreatePaymentConsentV3UnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreatePaymentConsentV3UnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3TooManyRequests creates a CreatePaymentConsentV3TooManyRequests with default headers values
func NewCreatePaymentConsentV3TooManyRequests() *CreatePaymentConsentV3TooManyRequests {
	return &CreatePaymentConsentV3TooManyRequests{}
}

/*
CreatePaymentConsentV3TooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreatePaymentConsentV3TooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 too many requests response has a 2xx status code
func (o *CreatePaymentConsentV3TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 too many requests response has a 3xx status code
func (o *CreatePaymentConsentV3TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 too many requests response has a 4xx status code
func (o *CreatePaymentConsentV3TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent v3 too many requests response has a 5xx status code
func (o *CreatePaymentConsentV3TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent v3 too many requests response a status code equal to that given
func (o *CreatePaymentConsentV3TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create payment consent v3 too many requests response
func (o *CreatePaymentConsentV3TooManyRequests) Code() int {
	return 429
}

func (o *CreatePaymentConsentV3TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePaymentConsentV3TooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3TooManyRequests  %+v", 429, o.Payload)
}

func (o *CreatePaymentConsentV3TooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentV3InternalServerError creates a CreatePaymentConsentV3InternalServerError with default headers values
func NewCreatePaymentConsentV3InternalServerError() *CreatePaymentConsentV3InternalServerError {
	return &CreatePaymentConsentV3InternalServerError{}
}

/*
CreatePaymentConsentV3InternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreatePaymentConsentV3InternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent v3 internal server error response has a 2xx status code
func (o *CreatePaymentConsentV3InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent v3 internal server error response has a 3xx status code
func (o *CreatePaymentConsentV3InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent v3 internal server error response has a 4xx status code
func (o *CreatePaymentConsentV3InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create payment consent v3 internal server error response has a 5xx status code
func (o *CreatePaymentConsentV3InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create payment consent v3 internal server error response a status code equal to that given
func (o *CreatePaymentConsentV3InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create payment consent v3 internal server error response
func (o *CreatePaymentConsentV3InternalServerError) Code() int {
	return 500
}

func (o *CreatePaymentConsentV3InternalServerError) Error() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3InternalServerError  %+v", 500, o.Payload)
}

func (o *CreatePaymentConsentV3InternalServerError) String() string {
	return fmt.Sprintf("[POST /open-banking/payments/v3/consents][%d] createPaymentConsentV3InternalServerError  %+v", 500, o.Payload)
}

func (o *CreatePaymentConsentV3InternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentV3InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}