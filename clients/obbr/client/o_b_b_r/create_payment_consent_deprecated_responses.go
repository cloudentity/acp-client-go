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

// CreatePaymentConsentDeprecatedReader is a Reader for the CreatePaymentConsentDeprecated structure.
type CreatePaymentConsentDeprecatedReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreatePaymentConsentDeprecatedReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreatePaymentConsentDeprecatedCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreatePaymentConsentDeprecatedBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreatePaymentConsentDeprecatedUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreatePaymentConsentDeprecatedForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreatePaymentConsentDeprecatedMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreatePaymentConsentDeprecatedNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreatePaymentConsentDeprecatedUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreatePaymentConsentDeprecatedUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreatePaymentConsentDeprecatedTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreatePaymentConsentDeprecatedInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking-brasil/open-banking/payments/v1/consents] CreatePaymentConsentDeprecated", response, response.Code())
	}
}

// NewCreatePaymentConsentDeprecatedCreated creates a CreatePaymentConsentDeprecatedCreated with default headers values
func NewCreatePaymentConsentDeprecatedCreated() *CreatePaymentConsentDeprecatedCreated {
	return &CreatePaymentConsentDeprecatedCreated{}
}

/*
CreatePaymentConsentDeprecatedCreated describes a response with status code 201, with default header values.

Customer payment consent
*/
type CreatePaymentConsentDeprecatedCreated struct {
	Payload *models.BrazilCustomerPaymentConsentResponse
}

// IsSuccess returns true when this create payment consent deprecated created response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create payment consent deprecated created response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated created response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create payment consent deprecated created response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated created response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create payment consent deprecated created response
func (o *CreatePaymentConsentDeprecatedCreated) Code() int {
	return 201
}

func (o *CreatePaymentConsentDeprecatedCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedCreated %s", 201, payload)
}

func (o *CreatePaymentConsentDeprecatedCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedCreated %s", 201, payload)
}

func (o *CreatePaymentConsentDeprecatedCreated) GetPayload() *models.BrazilCustomerPaymentConsentResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedBadRequest creates a CreatePaymentConsentDeprecatedBadRequest with default headers values
func NewCreatePaymentConsentDeprecatedBadRequest() *CreatePaymentConsentDeprecatedBadRequest {
	return &CreatePaymentConsentDeprecatedBadRequest{}
}

/*
CreatePaymentConsentDeprecatedBadRequest describes a response with status code 400, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated bad request response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated bad request response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated bad request response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated bad request response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated bad request response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create payment consent deprecated bad request response
func (o *CreatePaymentConsentDeprecatedBadRequest) Code() int {
	return 400
}

func (o *CreatePaymentConsentDeprecatedBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedBadRequest %s", 400, payload)
}

func (o *CreatePaymentConsentDeprecatedBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedBadRequest %s", 400, payload)
}

func (o *CreatePaymentConsentDeprecatedBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedUnauthorized creates a CreatePaymentConsentDeprecatedUnauthorized with default headers values
func NewCreatePaymentConsentDeprecatedUnauthorized() *CreatePaymentConsentDeprecatedUnauthorized {
	return &CreatePaymentConsentDeprecatedUnauthorized{}
}

/*
CreatePaymentConsentDeprecatedUnauthorized describes a response with status code 401, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated unauthorized response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated unauthorized response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated unauthorized response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated unauthorized response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated unauthorized response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create payment consent deprecated unauthorized response
func (o *CreatePaymentConsentDeprecatedUnauthorized) Code() int {
	return 401
}

func (o *CreatePaymentConsentDeprecatedUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnauthorized %s", 401, payload)
}

func (o *CreatePaymentConsentDeprecatedUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnauthorized %s", 401, payload)
}

func (o *CreatePaymentConsentDeprecatedUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedForbidden creates a CreatePaymentConsentDeprecatedForbidden with default headers values
func NewCreatePaymentConsentDeprecatedForbidden() *CreatePaymentConsentDeprecatedForbidden {
	return &CreatePaymentConsentDeprecatedForbidden{}
}

/*
CreatePaymentConsentDeprecatedForbidden describes a response with status code 403, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated forbidden response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated forbidden response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated forbidden response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated forbidden response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated forbidden response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create payment consent deprecated forbidden response
func (o *CreatePaymentConsentDeprecatedForbidden) Code() int {
	return 403
}

func (o *CreatePaymentConsentDeprecatedForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedForbidden %s", 403, payload)
}

func (o *CreatePaymentConsentDeprecatedForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedForbidden %s", 403, payload)
}

func (o *CreatePaymentConsentDeprecatedForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedMethodNotAllowed creates a CreatePaymentConsentDeprecatedMethodNotAllowed with default headers values
func NewCreatePaymentConsentDeprecatedMethodNotAllowed() *CreatePaymentConsentDeprecatedMethodNotAllowed {
	return &CreatePaymentConsentDeprecatedMethodNotAllowed{}
}

/*
CreatePaymentConsentDeprecatedMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated method not allowed response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated method not allowed response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated method not allowed response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated method not allowed response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated method not allowed response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create payment consent deprecated method not allowed response
func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) Code() int {
	return 405
}

func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedMethodNotAllowed %s", 405, payload)
}

func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedMethodNotAllowed %s", 405, payload)
}

func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedNotAcceptable creates a CreatePaymentConsentDeprecatedNotAcceptable with default headers values
func NewCreatePaymentConsentDeprecatedNotAcceptable() *CreatePaymentConsentDeprecatedNotAcceptable {
	return &CreatePaymentConsentDeprecatedNotAcceptable{}
}

/*
CreatePaymentConsentDeprecatedNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated not acceptable response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated not acceptable response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated not acceptable response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated not acceptable response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated not acceptable response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create payment consent deprecated not acceptable response
func (o *CreatePaymentConsentDeprecatedNotAcceptable) Code() int {
	return 406
}

func (o *CreatePaymentConsentDeprecatedNotAcceptable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedNotAcceptable %s", 406, payload)
}

func (o *CreatePaymentConsentDeprecatedNotAcceptable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedNotAcceptable %s", 406, payload)
}

func (o *CreatePaymentConsentDeprecatedNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedUnsupportedMediaType creates a CreatePaymentConsentDeprecatedUnsupportedMediaType with default headers values
func NewCreatePaymentConsentDeprecatedUnsupportedMediaType() *CreatePaymentConsentDeprecatedUnsupportedMediaType {
	return &CreatePaymentConsentDeprecatedUnsupportedMediaType{}
}

/*
CreatePaymentConsentDeprecatedUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated unsupported media type response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated unsupported media type response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated unsupported media type response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated unsupported media type response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated unsupported media type response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create payment consent deprecated unsupported media type response
func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnsupportedMediaType %s", 415, payload)
}

func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnsupportedMediaType %s", 415, payload)
}

func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedUnprocessableEntity creates a CreatePaymentConsentDeprecatedUnprocessableEntity with default headers values
func NewCreatePaymentConsentDeprecatedUnprocessableEntity() *CreatePaymentConsentDeprecatedUnprocessableEntity {
	return &CreatePaymentConsentDeprecatedUnprocessableEntity{}
}

/*
CreatePaymentConsentDeprecatedUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated unprocessable entity response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated unprocessable entity response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated unprocessable entity response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated unprocessable entity response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated unprocessable entity response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create payment consent deprecated unprocessable entity response
func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) Code() int {
	return 422
}

func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnprocessableEntity %s", 422, payload)
}

func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedUnprocessableEntity %s", 422, payload)
}

func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedTooManyRequests creates a CreatePaymentConsentDeprecatedTooManyRequests with default headers values
func NewCreatePaymentConsentDeprecatedTooManyRequests() *CreatePaymentConsentDeprecatedTooManyRequests {
	return &CreatePaymentConsentDeprecatedTooManyRequests{}
}

/*
CreatePaymentConsentDeprecatedTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated too many requests response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated too many requests response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated too many requests response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create payment consent deprecated too many requests response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create payment consent deprecated too many requests response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create payment consent deprecated too many requests response
func (o *CreatePaymentConsentDeprecatedTooManyRequests) Code() int {
	return 429
}

func (o *CreatePaymentConsentDeprecatedTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedTooManyRequests %s", 429, payload)
}

func (o *CreatePaymentConsentDeprecatedTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedTooManyRequests %s", 429, payload)
}

func (o *CreatePaymentConsentDeprecatedTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreatePaymentConsentDeprecatedInternalServerError creates a CreatePaymentConsentDeprecatedInternalServerError with default headers values
func NewCreatePaymentConsentDeprecatedInternalServerError() *CreatePaymentConsentDeprecatedInternalServerError {
	return &CreatePaymentConsentDeprecatedInternalServerError{}
}

/*
CreatePaymentConsentDeprecatedInternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreatePaymentConsentDeprecatedInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create payment consent deprecated internal server error response has a 2xx status code
func (o *CreatePaymentConsentDeprecatedInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create payment consent deprecated internal server error response has a 3xx status code
func (o *CreatePaymentConsentDeprecatedInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create payment consent deprecated internal server error response has a 4xx status code
func (o *CreatePaymentConsentDeprecatedInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create payment consent deprecated internal server error response has a 5xx status code
func (o *CreatePaymentConsentDeprecatedInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create payment consent deprecated internal server error response a status code equal to that given
func (o *CreatePaymentConsentDeprecatedInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create payment consent deprecated internal server error response
func (o *CreatePaymentConsentDeprecatedInternalServerError) Code() int {
	return 500
}

func (o *CreatePaymentConsentDeprecatedInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedInternalServerError %s", 500, payload)
}

func (o *CreatePaymentConsentDeprecatedInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v1/consents][%d] createPaymentConsentDeprecatedInternalServerError %s", 500, payload)
}

func (o *CreatePaymentConsentDeprecatedInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreatePaymentConsentDeprecatedInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
