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

// CreateDomesticScheduledPaymentConsentRequestReader is a Reader for the CreateDomesticScheduledPaymentConsentRequest structure.
type CreateDomesticScheduledPaymentConsentRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateDomesticScheduledPaymentConsentRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateDomesticScheduledPaymentConsentRequestCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateDomesticScheduledPaymentConsentRequestBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateDomesticScheduledPaymentConsentRequestUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateDomesticScheduledPaymentConsentRequestForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateDomesticScheduledPaymentConsentRequestMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateDomesticScheduledPaymentConsentRequestNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateDomesticScheduledPaymentConsentRequestTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateDomesticScheduledPaymentConsentRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents] createDomesticScheduledPaymentConsentRequest", response, response.Code())
	}
}

// NewCreateDomesticScheduledPaymentConsentRequestCreated creates a CreateDomesticScheduledPaymentConsentRequestCreated with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestCreated() *CreateDomesticScheduledPaymentConsentRequestCreated {
	return &CreateDomesticScheduledPaymentConsentRequestCreated{}
}

/*
CreateDomesticScheduledPaymentConsentRequestCreated describes a response with status code 201, with default header values.

Domestic scheduled payment consent
*/
type CreateDomesticScheduledPaymentConsentRequestCreated struct {
	Payload *models.DomesticScheduledPaymentConsentResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request created response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create domestic scheduled payment consent request created response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request created response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create domestic scheduled payment consent request created response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request created response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create domestic scheduled payment consent request created response
func (o *CreateDomesticScheduledPaymentConsentRequestCreated) Code() int {
	return 201
}

func (o *CreateDomesticScheduledPaymentConsentRequestCreated) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestCreated  %+v", 201, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestCreated) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestCreated  %+v", 201, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestCreated) GetPayload() *models.DomesticScheduledPaymentConsentResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DomesticScheduledPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestBadRequest creates a CreateDomesticScheduledPaymentConsentRequestBadRequest with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestBadRequest() *CreateDomesticScheduledPaymentConsentRequestBadRequest {
	return &CreateDomesticScheduledPaymentConsentRequestBadRequest{}
}

/*
CreateDomesticScheduledPaymentConsentRequestBadRequest describes a response with status code 400, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request bad request response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request bad request response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request bad request response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request bad request response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request bad request response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create domestic scheduled payment consent request bad request response
func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) Code() int {
	return 400
}

func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestUnauthorized creates a CreateDomesticScheduledPaymentConsentRequestUnauthorized with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestUnauthorized() *CreateDomesticScheduledPaymentConsentRequestUnauthorized {
	return &CreateDomesticScheduledPaymentConsentRequestUnauthorized{}
}

/*
CreateDomesticScheduledPaymentConsentRequestUnauthorized describes a response with status code 401, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request unauthorized response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request unauthorized response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request unauthorized response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request unauthorized response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request unauthorized response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create domestic scheduled payment consent request unauthorized response
func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) Code() int {
	return 401
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestForbidden creates a CreateDomesticScheduledPaymentConsentRequestForbidden with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestForbidden() *CreateDomesticScheduledPaymentConsentRequestForbidden {
	return &CreateDomesticScheduledPaymentConsentRequestForbidden{}
}

/*
CreateDomesticScheduledPaymentConsentRequestForbidden describes a response with status code 403, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request forbidden response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request forbidden response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request forbidden response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request forbidden response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request forbidden response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create domestic scheduled payment consent request forbidden response
func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) Code() int {
	return 403
}

func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestForbidden  %+v", 403, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestMethodNotAllowed creates a CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestMethodNotAllowed() *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed {
	return &CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed{}
}

/*
CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request method not allowed response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request method not allowed response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request method not allowed response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request method not allowed response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request method not allowed response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create domestic scheduled payment consent request method not allowed response
func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestNotAcceptable creates a CreateDomesticScheduledPaymentConsentRequestNotAcceptable with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestNotAcceptable() *CreateDomesticScheduledPaymentConsentRequestNotAcceptable {
	return &CreateDomesticScheduledPaymentConsentRequestNotAcceptable{}
}

/*
CreateDomesticScheduledPaymentConsentRequestNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request not acceptable response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request not acceptable response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request not acceptable response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request not acceptable response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request not acceptable response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create domestic scheduled payment consent request not acceptable response
func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) Code() int {
	return 406
}

func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestNotAcceptable  %+v", 406, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType creates a CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType() *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType {
	return &CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType{}
}

/*
CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request unsupported media type response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request unsupported media type response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request unsupported media type response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request unsupported media type response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request unsupported media type response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create domestic scheduled payment consent request unsupported media type response
func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestTooManyRequests creates a CreateDomesticScheduledPaymentConsentRequestTooManyRequests with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestTooManyRequests() *CreateDomesticScheduledPaymentConsentRequestTooManyRequests {
	return &CreateDomesticScheduledPaymentConsentRequestTooManyRequests{}
}

/*
CreateDomesticScheduledPaymentConsentRequestTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request too many requests response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request too many requests response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request too many requests response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create domestic scheduled payment consent request too many requests response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create domestic scheduled payment consent request too many requests response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create domestic scheduled payment consent request too many requests response
func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) Code() int {
	return 429
}

func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDomesticScheduledPaymentConsentRequestInternalServerError creates a CreateDomesticScheduledPaymentConsentRequestInternalServerError with default headers values
func NewCreateDomesticScheduledPaymentConsentRequestInternalServerError() *CreateDomesticScheduledPaymentConsentRequestInternalServerError {
	return &CreateDomesticScheduledPaymentConsentRequestInternalServerError{}
}

/*
CreateDomesticScheduledPaymentConsentRequestInternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreateDomesticScheduledPaymentConsentRequestInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create domestic scheduled payment consent request internal server error response has a 2xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create domestic scheduled payment consent request internal server error response has a 3xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create domestic scheduled payment consent request internal server error response has a 4xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create domestic scheduled payment consent request internal server error response has a 5xx status code
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create domestic scheduled payment consent request internal server error response a status code equal to that given
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create domestic scheduled payment consent request internal server error response
func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) Code() int {
	return 500
}

func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-scheduled-payment-consents][%d] createDomesticScheduledPaymentConsentRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateDomesticScheduledPaymentConsentRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
