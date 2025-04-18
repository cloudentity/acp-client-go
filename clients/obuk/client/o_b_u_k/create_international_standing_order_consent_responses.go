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

// CreateInternationalStandingOrderConsentReader is a Reader for the CreateInternationalStandingOrderConsent structure.
type CreateInternationalStandingOrderConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateInternationalStandingOrderConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateInternationalStandingOrderConsentCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateInternationalStandingOrderConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateInternationalStandingOrderConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateInternationalStandingOrderConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateInternationalStandingOrderConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateInternationalStandingOrderConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateInternationalStandingOrderConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateInternationalStandingOrderConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateInternationalStandingOrderConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/v3.1/pisp/international-standing-order-consents] createInternationalStandingOrderConsent", response, response.Code())
	}
}

// NewCreateInternationalStandingOrderConsentCreated creates a CreateInternationalStandingOrderConsentCreated with default headers values
func NewCreateInternationalStandingOrderConsentCreated() *CreateInternationalStandingOrderConsentCreated {
	return &CreateInternationalStandingOrderConsentCreated{}
}

/*
CreateInternationalStandingOrderConsentCreated describes a response with status code 201, with default header values.

International standing order consent
*/
type CreateInternationalStandingOrderConsentCreated struct {
	Payload *models.InternationalStandingOrderConsentResponse
}

// IsSuccess returns true when this create international standing order consent created response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create international standing order consent created response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent created response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international standing order consent created response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent created response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create international standing order consent created response
func (o *CreateInternationalStandingOrderConsentCreated) Code() int {
	return 201
}

func (o *CreateInternationalStandingOrderConsentCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentCreated %s", 201, payload)
}

func (o *CreateInternationalStandingOrderConsentCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentCreated %s", 201, payload)
}

func (o *CreateInternationalStandingOrderConsentCreated) GetPayload() *models.InternationalStandingOrderConsentResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.InternationalStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentBadRequest creates a CreateInternationalStandingOrderConsentBadRequest with default headers values
func NewCreateInternationalStandingOrderConsentBadRequest() *CreateInternationalStandingOrderConsentBadRequest {
	return &CreateInternationalStandingOrderConsentBadRequest{}
}

/*
CreateInternationalStandingOrderConsentBadRequest describes a response with status code 400, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent bad request response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent bad request response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent bad request response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent bad request response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent bad request response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create international standing order consent bad request response
func (o *CreateInternationalStandingOrderConsentBadRequest) Code() int {
	return 400
}

func (o *CreateInternationalStandingOrderConsentBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentBadRequest %s", 400, payload)
}

func (o *CreateInternationalStandingOrderConsentBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentBadRequest %s", 400, payload)
}

func (o *CreateInternationalStandingOrderConsentBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentUnauthorized creates a CreateInternationalStandingOrderConsentUnauthorized with default headers values
func NewCreateInternationalStandingOrderConsentUnauthorized() *CreateInternationalStandingOrderConsentUnauthorized {
	return &CreateInternationalStandingOrderConsentUnauthorized{}
}

/*
CreateInternationalStandingOrderConsentUnauthorized describes a response with status code 401, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentUnauthorized struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent unauthorized response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent unauthorized response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent unauthorized response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent unauthorized response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent unauthorized response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create international standing order consent unauthorized response
func (o *CreateInternationalStandingOrderConsentUnauthorized) Code() int {
	return 401
}

func (o *CreateInternationalStandingOrderConsentUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentUnauthorized %s", 401, payload)
}

func (o *CreateInternationalStandingOrderConsentUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentUnauthorized %s", 401, payload)
}

func (o *CreateInternationalStandingOrderConsentUnauthorized) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentForbidden creates a CreateInternationalStandingOrderConsentForbidden with default headers values
func NewCreateInternationalStandingOrderConsentForbidden() *CreateInternationalStandingOrderConsentForbidden {
	return &CreateInternationalStandingOrderConsentForbidden{}
}

/*
CreateInternationalStandingOrderConsentForbidden describes a response with status code 403, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent forbidden response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent forbidden response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent forbidden response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent forbidden response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent forbidden response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create international standing order consent forbidden response
func (o *CreateInternationalStandingOrderConsentForbidden) Code() int {
	return 403
}

func (o *CreateInternationalStandingOrderConsentForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentForbidden %s", 403, payload)
}

func (o *CreateInternationalStandingOrderConsentForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentForbidden %s", 403, payload)
}

func (o *CreateInternationalStandingOrderConsentForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentMethodNotAllowed creates a CreateInternationalStandingOrderConsentMethodNotAllowed with default headers values
func NewCreateInternationalStandingOrderConsentMethodNotAllowed() *CreateInternationalStandingOrderConsentMethodNotAllowed {
	return &CreateInternationalStandingOrderConsentMethodNotAllowed{}
}

/*
CreateInternationalStandingOrderConsentMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentMethodNotAllowed struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent method not allowed response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent method not allowed response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent method not allowed response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent method not allowed response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent method not allowed response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create international standing order consent method not allowed response
func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentMethodNotAllowed %s", 405, payload)
}

func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentMethodNotAllowed %s", 405, payload)
}

func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentNotAcceptable creates a CreateInternationalStandingOrderConsentNotAcceptable with default headers values
func NewCreateInternationalStandingOrderConsentNotAcceptable() *CreateInternationalStandingOrderConsentNotAcceptable {
	return &CreateInternationalStandingOrderConsentNotAcceptable{}
}

/*
CreateInternationalStandingOrderConsentNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentNotAcceptable struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent not acceptable response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent not acceptable response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent not acceptable response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent not acceptable response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent not acceptable response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create international standing order consent not acceptable response
func (o *CreateInternationalStandingOrderConsentNotAcceptable) Code() int {
	return 406
}

func (o *CreateInternationalStandingOrderConsentNotAcceptable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentNotAcceptable %s", 406, payload)
}

func (o *CreateInternationalStandingOrderConsentNotAcceptable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentNotAcceptable %s", 406, payload)
}

func (o *CreateInternationalStandingOrderConsentNotAcceptable) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentUnsupportedMediaType creates a CreateInternationalStandingOrderConsentUnsupportedMediaType with default headers values
func NewCreateInternationalStandingOrderConsentUnsupportedMediaType() *CreateInternationalStandingOrderConsentUnsupportedMediaType {
	return &CreateInternationalStandingOrderConsentUnsupportedMediaType{}
}

/*
CreateInternationalStandingOrderConsentUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentUnsupportedMediaType struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent unsupported media type response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent unsupported media type response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent unsupported media type response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent unsupported media type response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent unsupported media type response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create international standing order consent unsupported media type response
func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentUnsupportedMediaType %s", 415, payload)
}

func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentUnsupportedMediaType %s", 415, payload)
}

func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentTooManyRequests creates a CreateInternationalStandingOrderConsentTooManyRequests with default headers values
func NewCreateInternationalStandingOrderConsentTooManyRequests() *CreateInternationalStandingOrderConsentTooManyRequests {
	return &CreateInternationalStandingOrderConsentTooManyRequests{}
}

/*
CreateInternationalStandingOrderConsentTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentTooManyRequests struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent too many requests response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent too many requests response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent too many requests response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international standing order consent too many requests response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create international standing order consent too many requests response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create international standing order consent too many requests response
func (o *CreateInternationalStandingOrderConsentTooManyRequests) Code() int {
	return 429
}

func (o *CreateInternationalStandingOrderConsentTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentTooManyRequests %s", 429, payload)
}

func (o *CreateInternationalStandingOrderConsentTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentTooManyRequests %s", 429, payload)
}

func (o *CreateInternationalStandingOrderConsentTooManyRequests) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalStandingOrderConsentInternalServerError creates a CreateInternationalStandingOrderConsentInternalServerError with default headers values
func NewCreateInternationalStandingOrderConsentInternalServerError() *CreateInternationalStandingOrderConsentInternalServerError {
	return &CreateInternationalStandingOrderConsentInternalServerError{}
}

/*
CreateInternationalStandingOrderConsentInternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreateInternationalStandingOrderConsentInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this create international standing order consent internal server error response has a 2xx status code
func (o *CreateInternationalStandingOrderConsentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international standing order consent internal server error response has a 3xx status code
func (o *CreateInternationalStandingOrderConsentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international standing order consent internal server error response has a 4xx status code
func (o *CreateInternationalStandingOrderConsentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international standing order consent internal server error response has a 5xx status code
func (o *CreateInternationalStandingOrderConsentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create international standing order consent internal server error response a status code equal to that given
func (o *CreateInternationalStandingOrderConsentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create international standing order consent internal server error response
func (o *CreateInternationalStandingOrderConsentInternalServerError) Code() int {
	return 500
}

func (o *CreateInternationalStandingOrderConsentInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentInternalServerError %s", 500, payload)
}

func (o *CreateInternationalStandingOrderConsentInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents][%d] createInternationalStandingOrderConsentInternalServerError %s", 500, payload)
}

func (o *CreateInternationalStandingOrderConsentInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *CreateInternationalStandingOrderConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
