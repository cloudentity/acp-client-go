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

// CreateDataAccessConsentReader is a Reader for the CreateDataAccessConsent structure.
type CreateDataAccessConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateDataAccessConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateDataAccessConsentCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateDataAccessConsentBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateDataAccessConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateDataAccessConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateDataAccessConsentMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateDataAccessConsentNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateDataAccessConsentUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateDataAccessConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateDataAccessConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateDataAccessConsentInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/consents/v1/consents] CreateDataAccessConsent", response, response.Code())
	}
}

// NewCreateDataAccessConsentCreated creates a CreateDataAccessConsentCreated with default headers values
func NewCreateDataAccessConsentCreated() *CreateDataAccessConsentCreated {
	return &CreateDataAccessConsentCreated{}
}

/*
CreateDataAccessConsentCreated describes a response with status code 201, with default header values.

Customer data access consent
*/
type CreateDataAccessConsentCreated struct {
	Payload *models.BrazilCustomerDataAccessConsentResponse
}

// IsSuccess returns true when this create data access consent created response has a 2xx status code
func (o *CreateDataAccessConsentCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create data access consent created response has a 3xx status code
func (o *CreateDataAccessConsentCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent created response has a 4xx status code
func (o *CreateDataAccessConsentCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create data access consent created response has a 5xx status code
func (o *CreateDataAccessConsentCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent created response a status code equal to that given
func (o *CreateDataAccessConsentCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create data access consent created response
func (o *CreateDataAccessConsentCreated) Code() int {
	return 201
}

func (o *CreateDataAccessConsentCreated) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentCreated  %+v", 201, o.Payload)
}

func (o *CreateDataAccessConsentCreated) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentCreated  %+v", 201, o.Payload)
}

func (o *CreateDataAccessConsentCreated) GetPayload() *models.BrazilCustomerDataAccessConsentResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerDataAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentBadRequest creates a CreateDataAccessConsentBadRequest with default headers values
func NewCreateDataAccessConsentBadRequest() *CreateDataAccessConsentBadRequest {
	return &CreateDataAccessConsentBadRequest{}
}

/*
CreateDataAccessConsentBadRequest describes a response with status code 400, with default header values.

Error
*/
type CreateDataAccessConsentBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent bad request response has a 2xx status code
func (o *CreateDataAccessConsentBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent bad request response has a 3xx status code
func (o *CreateDataAccessConsentBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent bad request response has a 4xx status code
func (o *CreateDataAccessConsentBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent bad request response has a 5xx status code
func (o *CreateDataAccessConsentBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent bad request response a status code equal to that given
func (o *CreateDataAccessConsentBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create data access consent bad request response
func (o *CreateDataAccessConsentBadRequest) Code() int {
	return 400
}

func (o *CreateDataAccessConsentBadRequest) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDataAccessConsentBadRequest) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentBadRequest  %+v", 400, o.Payload)
}

func (o *CreateDataAccessConsentBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnauthorized creates a CreateDataAccessConsentUnauthorized with default headers values
func NewCreateDataAccessConsentUnauthorized() *CreateDataAccessConsentUnauthorized {
	return &CreateDataAccessConsentUnauthorized{}
}

/*
CreateDataAccessConsentUnauthorized describes a response with status code 401, with default header values.

Error
*/
type CreateDataAccessConsentUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent unauthorized response has a 2xx status code
func (o *CreateDataAccessConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent unauthorized response has a 3xx status code
func (o *CreateDataAccessConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent unauthorized response has a 4xx status code
func (o *CreateDataAccessConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent unauthorized response has a 5xx status code
func (o *CreateDataAccessConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent unauthorized response a status code equal to that given
func (o *CreateDataAccessConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create data access consent unauthorized response
func (o *CreateDataAccessConsentUnauthorized) Code() int {
	return 401
}

func (o *CreateDataAccessConsentUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateDataAccessConsentUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateDataAccessConsentUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentForbidden creates a CreateDataAccessConsentForbidden with default headers values
func NewCreateDataAccessConsentForbidden() *CreateDataAccessConsentForbidden {
	return &CreateDataAccessConsentForbidden{}
}

/*
CreateDataAccessConsentForbidden describes a response with status code 403, with default header values.

Error
*/
type CreateDataAccessConsentForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent forbidden response has a 2xx status code
func (o *CreateDataAccessConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent forbidden response has a 3xx status code
func (o *CreateDataAccessConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent forbidden response has a 4xx status code
func (o *CreateDataAccessConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent forbidden response has a 5xx status code
func (o *CreateDataAccessConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent forbidden response a status code equal to that given
func (o *CreateDataAccessConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create data access consent forbidden response
func (o *CreateDataAccessConsentForbidden) Code() int {
	return 403
}

func (o *CreateDataAccessConsentForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentForbidden  %+v", 403, o.Payload)
}

func (o *CreateDataAccessConsentForbidden) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentForbidden  %+v", 403, o.Payload)
}

func (o *CreateDataAccessConsentForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentMethodNotAllowed creates a CreateDataAccessConsentMethodNotAllowed with default headers values
func NewCreateDataAccessConsentMethodNotAllowed() *CreateDataAccessConsentMethodNotAllowed {
	return &CreateDataAccessConsentMethodNotAllowed{}
}

/*
CreateDataAccessConsentMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreateDataAccessConsentMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent method not allowed response has a 2xx status code
func (o *CreateDataAccessConsentMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent method not allowed response has a 3xx status code
func (o *CreateDataAccessConsentMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent method not allowed response has a 4xx status code
func (o *CreateDataAccessConsentMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent method not allowed response has a 5xx status code
func (o *CreateDataAccessConsentMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent method not allowed response a status code equal to that given
func (o *CreateDataAccessConsentMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create data access consent method not allowed response
func (o *CreateDataAccessConsentMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateDataAccessConsentMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreateDataAccessConsentMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *CreateDataAccessConsentMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentNotAcceptable creates a CreateDataAccessConsentNotAcceptable with default headers values
func NewCreateDataAccessConsentNotAcceptable() *CreateDataAccessConsentNotAcceptable {
	return &CreateDataAccessConsentNotAcceptable{}
}

/*
CreateDataAccessConsentNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreateDataAccessConsentNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent not acceptable response has a 2xx status code
func (o *CreateDataAccessConsentNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent not acceptable response has a 3xx status code
func (o *CreateDataAccessConsentNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent not acceptable response has a 4xx status code
func (o *CreateDataAccessConsentNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent not acceptable response has a 5xx status code
func (o *CreateDataAccessConsentNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent not acceptable response a status code equal to that given
func (o *CreateDataAccessConsentNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create data access consent not acceptable response
func (o *CreateDataAccessConsentNotAcceptable) Code() int {
	return 406
}

func (o *CreateDataAccessConsentNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *CreateDataAccessConsentNotAcceptable) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentNotAcceptable  %+v", 406, o.Payload)
}

func (o *CreateDataAccessConsentNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnsupportedMediaType creates a CreateDataAccessConsentUnsupportedMediaType with default headers values
func NewCreateDataAccessConsentUnsupportedMediaType() *CreateDataAccessConsentUnsupportedMediaType {
	return &CreateDataAccessConsentUnsupportedMediaType{}
}

/*
CreateDataAccessConsentUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreateDataAccessConsentUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent unsupported media type response has a 2xx status code
func (o *CreateDataAccessConsentUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent unsupported media type response has a 3xx status code
func (o *CreateDataAccessConsentUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent unsupported media type response has a 4xx status code
func (o *CreateDataAccessConsentUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent unsupported media type response has a 5xx status code
func (o *CreateDataAccessConsentUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent unsupported media type response a status code equal to that given
func (o *CreateDataAccessConsentUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create data access consent unsupported media type response
func (o *CreateDataAccessConsentUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateDataAccessConsentUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreateDataAccessConsentUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *CreateDataAccessConsentUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentUnprocessableEntity creates a CreateDataAccessConsentUnprocessableEntity with default headers values
func NewCreateDataAccessConsentUnprocessableEntity() *CreateDataAccessConsentUnprocessableEntity {
	return &CreateDataAccessConsentUnprocessableEntity{}
}

/*
CreateDataAccessConsentUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type CreateDataAccessConsentUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent unprocessable entity response has a 2xx status code
func (o *CreateDataAccessConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent unprocessable entity response has a 3xx status code
func (o *CreateDataAccessConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent unprocessable entity response has a 4xx status code
func (o *CreateDataAccessConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent unprocessable entity response has a 5xx status code
func (o *CreateDataAccessConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent unprocessable entity response a status code equal to that given
func (o *CreateDataAccessConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create data access consent unprocessable entity response
func (o *CreateDataAccessConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *CreateDataAccessConsentUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateDataAccessConsentUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *CreateDataAccessConsentUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentTooManyRequests creates a CreateDataAccessConsentTooManyRequests with default headers values
func NewCreateDataAccessConsentTooManyRequests() *CreateDataAccessConsentTooManyRequests {
	return &CreateDataAccessConsentTooManyRequests{}
}

/*
CreateDataAccessConsentTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreateDataAccessConsentTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent too many requests response has a 2xx status code
func (o *CreateDataAccessConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent too many requests response has a 3xx status code
func (o *CreateDataAccessConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent too many requests response has a 4xx status code
func (o *CreateDataAccessConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent too many requests response has a 5xx status code
func (o *CreateDataAccessConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent too many requests response a status code equal to that given
func (o *CreateDataAccessConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create data access consent too many requests response
func (o *CreateDataAccessConsentTooManyRequests) Code() int {
	return 429
}

func (o *CreateDataAccessConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDataAccessConsentTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *CreateDataAccessConsentTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentInternalServerError creates a CreateDataAccessConsentInternalServerError with default headers values
func NewCreateDataAccessConsentInternalServerError() *CreateDataAccessConsentInternalServerError {
	return &CreateDataAccessConsentInternalServerError{}
}

/*
CreateDataAccessConsentInternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreateDataAccessConsentInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent internal server error response has a 2xx status code
func (o *CreateDataAccessConsentInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent internal server error response has a 3xx status code
func (o *CreateDataAccessConsentInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent internal server error response has a 4xx status code
func (o *CreateDataAccessConsentInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create data access consent internal server error response has a 5xx status code
func (o *CreateDataAccessConsentInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create data access consent internal server error response a status code equal to that given
func (o *CreateDataAccessConsentInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create data access consent internal server error response
func (o *CreateDataAccessConsentInternalServerError) Code() int {
	return 500
}

func (o *CreateDataAccessConsentInternalServerError) Error() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDataAccessConsentInternalServerError) String() string {
	return fmt.Sprintf("[POST /open-banking/consents/v1/consents][%d] createDataAccessConsentInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateDataAccessConsentInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
