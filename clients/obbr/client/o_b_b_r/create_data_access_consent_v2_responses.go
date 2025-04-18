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

// CreateDataAccessConsentV2Reader is a Reader for the CreateDataAccessConsentV2 structure.
type CreateDataAccessConsentV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateDataAccessConsentV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateDataAccessConsentV2Created()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateDataAccessConsentV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateDataAccessConsentV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateDataAccessConsentV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateDataAccessConsentV2MethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateDataAccessConsentV2NotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateDataAccessConsentV2UnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCreateDataAccessConsentV2UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateDataAccessConsentV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateDataAccessConsentV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/consents/v2/consents] CreateDataAccessConsentV2", response, response.Code())
	}
}

// NewCreateDataAccessConsentV2Created creates a CreateDataAccessConsentV2Created with default headers values
func NewCreateDataAccessConsentV2Created() *CreateDataAccessConsentV2Created {
	return &CreateDataAccessConsentV2Created{}
}

/*
CreateDataAccessConsentV2Created describes a response with status code 201, with default header values.

Create Customer data access v2 consent
*/
type CreateDataAccessConsentV2Created struct {
	Payload *models.BrazilCreateCustomerDataAccessConsentV2Response
}

// IsSuccess returns true when this create data access consent v2 created response has a 2xx status code
func (o *CreateDataAccessConsentV2Created) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create data access consent v2 created response has a 3xx status code
func (o *CreateDataAccessConsentV2Created) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 created response has a 4xx status code
func (o *CreateDataAccessConsentV2Created) IsClientError() bool {
	return false
}

// IsServerError returns true when this create data access consent v2 created response has a 5xx status code
func (o *CreateDataAccessConsentV2Created) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 created response a status code equal to that given
func (o *CreateDataAccessConsentV2Created) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create data access consent v2 created response
func (o *CreateDataAccessConsentV2Created) Code() int {
	return 201
}

func (o *CreateDataAccessConsentV2Created) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Created %s", 201, payload)
}

func (o *CreateDataAccessConsentV2Created) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Created %s", 201, payload)
}

func (o *CreateDataAccessConsentV2Created) GetPayload() *models.BrazilCreateCustomerDataAccessConsentV2Response {
	return o.Payload
}

func (o *CreateDataAccessConsentV2Created) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCreateCustomerDataAccessConsentV2Response)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2BadRequest creates a CreateDataAccessConsentV2BadRequest with default headers values
func NewCreateDataAccessConsentV2BadRequest() *CreateDataAccessConsentV2BadRequest {
	return &CreateDataAccessConsentV2BadRequest{}
}

/*
CreateDataAccessConsentV2BadRequest describes a response with status code 400, with default header values.

Error
*/
type CreateDataAccessConsentV2BadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 bad request response has a 2xx status code
func (o *CreateDataAccessConsentV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 bad request response has a 3xx status code
func (o *CreateDataAccessConsentV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 bad request response has a 4xx status code
func (o *CreateDataAccessConsentV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 bad request response has a 5xx status code
func (o *CreateDataAccessConsentV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 bad request response a status code equal to that given
func (o *CreateDataAccessConsentV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create data access consent v2 bad request response
func (o *CreateDataAccessConsentV2BadRequest) Code() int {
	return 400
}

func (o *CreateDataAccessConsentV2BadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2BadRequest %s", 400, payload)
}

func (o *CreateDataAccessConsentV2BadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2BadRequest %s", 400, payload)
}

func (o *CreateDataAccessConsentV2BadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2Unauthorized creates a CreateDataAccessConsentV2Unauthorized with default headers values
func NewCreateDataAccessConsentV2Unauthorized() *CreateDataAccessConsentV2Unauthorized {
	return &CreateDataAccessConsentV2Unauthorized{}
}

/*
CreateDataAccessConsentV2Unauthorized describes a response with status code 401, with default header values.

Error
*/
type CreateDataAccessConsentV2Unauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 unauthorized response has a 2xx status code
func (o *CreateDataAccessConsentV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 unauthorized response has a 3xx status code
func (o *CreateDataAccessConsentV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 unauthorized response has a 4xx status code
func (o *CreateDataAccessConsentV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 unauthorized response has a 5xx status code
func (o *CreateDataAccessConsentV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 unauthorized response a status code equal to that given
func (o *CreateDataAccessConsentV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create data access consent v2 unauthorized response
func (o *CreateDataAccessConsentV2Unauthorized) Code() int {
	return 401
}

func (o *CreateDataAccessConsentV2Unauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Unauthorized %s", 401, payload)
}

func (o *CreateDataAccessConsentV2Unauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Unauthorized %s", 401, payload)
}

func (o *CreateDataAccessConsentV2Unauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2Forbidden creates a CreateDataAccessConsentV2Forbidden with default headers values
func NewCreateDataAccessConsentV2Forbidden() *CreateDataAccessConsentV2Forbidden {
	return &CreateDataAccessConsentV2Forbidden{}
}

/*
CreateDataAccessConsentV2Forbidden describes a response with status code 403, with default header values.

Error
*/
type CreateDataAccessConsentV2Forbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 forbidden response has a 2xx status code
func (o *CreateDataAccessConsentV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 forbidden response has a 3xx status code
func (o *CreateDataAccessConsentV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 forbidden response has a 4xx status code
func (o *CreateDataAccessConsentV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 forbidden response has a 5xx status code
func (o *CreateDataAccessConsentV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 forbidden response a status code equal to that given
func (o *CreateDataAccessConsentV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create data access consent v2 forbidden response
func (o *CreateDataAccessConsentV2Forbidden) Code() int {
	return 403
}

func (o *CreateDataAccessConsentV2Forbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Forbidden %s", 403, payload)
}

func (o *CreateDataAccessConsentV2Forbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2Forbidden %s", 403, payload)
}

func (o *CreateDataAccessConsentV2Forbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2MethodNotAllowed creates a CreateDataAccessConsentV2MethodNotAllowed with default headers values
func NewCreateDataAccessConsentV2MethodNotAllowed() *CreateDataAccessConsentV2MethodNotAllowed {
	return &CreateDataAccessConsentV2MethodNotAllowed{}
}

/*
CreateDataAccessConsentV2MethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type CreateDataAccessConsentV2MethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 method not allowed response has a 2xx status code
func (o *CreateDataAccessConsentV2MethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 method not allowed response has a 3xx status code
func (o *CreateDataAccessConsentV2MethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 method not allowed response has a 4xx status code
func (o *CreateDataAccessConsentV2MethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 method not allowed response has a 5xx status code
func (o *CreateDataAccessConsentV2MethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 method not allowed response a status code equal to that given
func (o *CreateDataAccessConsentV2MethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create data access consent v2 method not allowed response
func (o *CreateDataAccessConsentV2MethodNotAllowed) Code() int {
	return 405
}

func (o *CreateDataAccessConsentV2MethodNotAllowed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2MethodNotAllowed %s", 405, payload)
}

func (o *CreateDataAccessConsentV2MethodNotAllowed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2MethodNotAllowed %s", 405, payload)
}

func (o *CreateDataAccessConsentV2MethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2MethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2NotAcceptable creates a CreateDataAccessConsentV2NotAcceptable with default headers values
func NewCreateDataAccessConsentV2NotAcceptable() *CreateDataAccessConsentV2NotAcceptable {
	return &CreateDataAccessConsentV2NotAcceptable{}
}

/*
CreateDataAccessConsentV2NotAcceptable describes a response with status code 406, with default header values.

Error
*/
type CreateDataAccessConsentV2NotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 not acceptable response has a 2xx status code
func (o *CreateDataAccessConsentV2NotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 not acceptable response has a 3xx status code
func (o *CreateDataAccessConsentV2NotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 not acceptable response has a 4xx status code
func (o *CreateDataAccessConsentV2NotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 not acceptable response has a 5xx status code
func (o *CreateDataAccessConsentV2NotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 not acceptable response a status code equal to that given
func (o *CreateDataAccessConsentV2NotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create data access consent v2 not acceptable response
func (o *CreateDataAccessConsentV2NotAcceptable) Code() int {
	return 406
}

func (o *CreateDataAccessConsentV2NotAcceptable) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2NotAcceptable %s", 406, payload)
}

func (o *CreateDataAccessConsentV2NotAcceptable) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2NotAcceptable %s", 406, payload)
}

func (o *CreateDataAccessConsentV2NotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2NotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2UnsupportedMediaType creates a CreateDataAccessConsentV2UnsupportedMediaType with default headers values
func NewCreateDataAccessConsentV2UnsupportedMediaType() *CreateDataAccessConsentV2UnsupportedMediaType {
	return &CreateDataAccessConsentV2UnsupportedMediaType{}
}

/*
CreateDataAccessConsentV2UnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type CreateDataAccessConsentV2UnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 unsupported media type response has a 2xx status code
func (o *CreateDataAccessConsentV2UnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 unsupported media type response has a 3xx status code
func (o *CreateDataAccessConsentV2UnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 unsupported media type response has a 4xx status code
func (o *CreateDataAccessConsentV2UnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 unsupported media type response has a 5xx status code
func (o *CreateDataAccessConsentV2UnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 unsupported media type response a status code equal to that given
func (o *CreateDataAccessConsentV2UnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create data access consent v2 unsupported media type response
func (o *CreateDataAccessConsentV2UnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateDataAccessConsentV2UnsupportedMediaType) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2UnsupportedMediaType %s", 415, payload)
}

func (o *CreateDataAccessConsentV2UnsupportedMediaType) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2UnsupportedMediaType %s", 415, payload)
}

func (o *CreateDataAccessConsentV2UnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2UnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2UnprocessableEntity creates a CreateDataAccessConsentV2UnprocessableEntity with default headers values
func NewCreateDataAccessConsentV2UnprocessableEntity() *CreateDataAccessConsentV2UnprocessableEntity {
	return &CreateDataAccessConsentV2UnprocessableEntity{}
}

/*
CreateDataAccessConsentV2UnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type CreateDataAccessConsentV2UnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 unprocessable entity response has a 2xx status code
func (o *CreateDataAccessConsentV2UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 unprocessable entity response has a 3xx status code
func (o *CreateDataAccessConsentV2UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 unprocessable entity response has a 4xx status code
func (o *CreateDataAccessConsentV2UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 unprocessable entity response has a 5xx status code
func (o *CreateDataAccessConsentV2UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 unprocessable entity response a status code equal to that given
func (o *CreateDataAccessConsentV2UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the create data access consent v2 unprocessable entity response
func (o *CreateDataAccessConsentV2UnprocessableEntity) Code() int {
	return 422
}

func (o *CreateDataAccessConsentV2UnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2UnprocessableEntity %s", 422, payload)
}

func (o *CreateDataAccessConsentV2UnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2UnprocessableEntity %s", 422, payload)
}

func (o *CreateDataAccessConsentV2UnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2TooManyRequests creates a CreateDataAccessConsentV2TooManyRequests with default headers values
func NewCreateDataAccessConsentV2TooManyRequests() *CreateDataAccessConsentV2TooManyRequests {
	return &CreateDataAccessConsentV2TooManyRequests{}
}

/*
CreateDataAccessConsentV2TooManyRequests describes a response with status code 429, with default header values.

Error
*/
type CreateDataAccessConsentV2TooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 too many requests response has a 2xx status code
func (o *CreateDataAccessConsentV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 too many requests response has a 3xx status code
func (o *CreateDataAccessConsentV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 too many requests response has a 4xx status code
func (o *CreateDataAccessConsentV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create data access consent v2 too many requests response has a 5xx status code
func (o *CreateDataAccessConsentV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create data access consent v2 too many requests response a status code equal to that given
func (o *CreateDataAccessConsentV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create data access consent v2 too many requests response
func (o *CreateDataAccessConsentV2TooManyRequests) Code() int {
	return 429
}

func (o *CreateDataAccessConsentV2TooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2TooManyRequests %s", 429, payload)
}

func (o *CreateDataAccessConsentV2TooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2TooManyRequests %s", 429, payload)
}

func (o *CreateDataAccessConsentV2TooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateDataAccessConsentV2InternalServerError creates a CreateDataAccessConsentV2InternalServerError with default headers values
func NewCreateDataAccessConsentV2InternalServerError() *CreateDataAccessConsentV2InternalServerError {
	return &CreateDataAccessConsentV2InternalServerError{}
}

/*
CreateDataAccessConsentV2InternalServerError describes a response with status code 500, with default header values.

Error
*/
type CreateDataAccessConsentV2InternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this create data access consent v2 internal server error response has a 2xx status code
func (o *CreateDataAccessConsentV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create data access consent v2 internal server error response has a 3xx status code
func (o *CreateDataAccessConsentV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create data access consent v2 internal server error response has a 4xx status code
func (o *CreateDataAccessConsentV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create data access consent v2 internal server error response has a 5xx status code
func (o *CreateDataAccessConsentV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create data access consent v2 internal server error response a status code equal to that given
func (o *CreateDataAccessConsentV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create data access consent v2 internal server error response
func (o *CreateDataAccessConsentV2InternalServerError) Code() int {
	return 500
}

func (o *CreateDataAccessConsentV2InternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2InternalServerError %s", 500, payload)
}

func (o *CreateDataAccessConsentV2InternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/consents/v2/consents][%d] createDataAccessConsentV2InternalServerError %s", 500, payload)
}

func (o *CreateDataAccessConsentV2InternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *CreateDataAccessConsentV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
