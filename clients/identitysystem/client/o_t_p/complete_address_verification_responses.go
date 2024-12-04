// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// CompleteAddressVerificationReader is a Reader for the CompleteAddressVerification structure.
type CompleteAddressVerificationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CompleteAddressVerificationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCompleteAddressVerificationNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCompleteAddressVerificationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCompleteAddressVerificationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCompleteAddressVerificationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCompleteAddressVerificationConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewCompleteAddressVerificationPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewCompleteAddressVerificationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete] completeAddressVerification", response, response.Code())
	}
}

// NewCompleteAddressVerificationNoContent creates a CompleteAddressVerificationNoContent with default headers values
func NewCompleteAddressVerificationNoContent() *CompleteAddressVerificationNoContent {
	return &CompleteAddressVerificationNoContent{}
}

/*
CompleteAddressVerificationNoContent describes a response with status code 204, with default header values.

Complete address veritifaction response
*/
type CompleteAddressVerificationNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this complete address verification no content response has a 2xx status code
func (o *CompleteAddressVerificationNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this complete address verification no content response has a 3xx status code
func (o *CompleteAddressVerificationNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification no content response has a 4xx status code
func (o *CompleteAddressVerificationNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this complete address verification no content response has a 5xx status code
func (o *CompleteAddressVerificationNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification no content response a status code equal to that given
func (o *CompleteAddressVerificationNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the complete address verification no content response
func (o *CompleteAddressVerificationNoContent) Code() int {
	return 204
}

func (o *CompleteAddressVerificationNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationNoContent", 204)
}

func (o *CompleteAddressVerificationNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationNoContent", 204)
}

func (o *CompleteAddressVerificationNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewCompleteAddressVerificationBadRequest creates a CompleteAddressVerificationBadRequest with default headers values
func NewCompleteAddressVerificationBadRequest() *CompleteAddressVerificationBadRequest {
	return &CompleteAddressVerificationBadRequest{}
}

/*
CompleteAddressVerificationBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CompleteAddressVerificationBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification bad request response has a 2xx status code
func (o *CompleteAddressVerificationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification bad request response has a 3xx status code
func (o *CompleteAddressVerificationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification bad request response has a 4xx status code
func (o *CompleteAddressVerificationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification bad request response has a 5xx status code
func (o *CompleteAddressVerificationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification bad request response a status code equal to that given
func (o *CompleteAddressVerificationBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the complete address verification bad request response
func (o *CompleteAddressVerificationBadRequest) Code() int {
	return 400
}

func (o *CompleteAddressVerificationBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationBadRequest %s", 400, payload)
}

func (o *CompleteAddressVerificationBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationBadRequest %s", 400, payload)
}

func (o *CompleteAddressVerificationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteAddressVerificationUnauthorized creates a CompleteAddressVerificationUnauthorized with default headers values
func NewCompleteAddressVerificationUnauthorized() *CompleteAddressVerificationUnauthorized {
	return &CompleteAddressVerificationUnauthorized{}
}

/*
CompleteAddressVerificationUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CompleteAddressVerificationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification unauthorized response has a 2xx status code
func (o *CompleteAddressVerificationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification unauthorized response has a 3xx status code
func (o *CompleteAddressVerificationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification unauthorized response has a 4xx status code
func (o *CompleteAddressVerificationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification unauthorized response has a 5xx status code
func (o *CompleteAddressVerificationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification unauthorized response a status code equal to that given
func (o *CompleteAddressVerificationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the complete address verification unauthorized response
func (o *CompleteAddressVerificationUnauthorized) Code() int {
	return 401
}

func (o *CompleteAddressVerificationUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationUnauthorized %s", 401, payload)
}

func (o *CompleteAddressVerificationUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationUnauthorized %s", 401, payload)
}

func (o *CompleteAddressVerificationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteAddressVerificationNotFound creates a CompleteAddressVerificationNotFound with default headers values
func NewCompleteAddressVerificationNotFound() *CompleteAddressVerificationNotFound {
	return &CompleteAddressVerificationNotFound{}
}

/*
CompleteAddressVerificationNotFound describes a response with status code 404, with default header values.

Not found
*/
type CompleteAddressVerificationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification not found response has a 2xx status code
func (o *CompleteAddressVerificationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification not found response has a 3xx status code
func (o *CompleteAddressVerificationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification not found response has a 4xx status code
func (o *CompleteAddressVerificationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification not found response has a 5xx status code
func (o *CompleteAddressVerificationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification not found response a status code equal to that given
func (o *CompleteAddressVerificationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the complete address verification not found response
func (o *CompleteAddressVerificationNotFound) Code() int {
	return 404
}

func (o *CompleteAddressVerificationNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationNotFound %s", 404, payload)
}

func (o *CompleteAddressVerificationNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationNotFound %s", 404, payload)
}

func (o *CompleteAddressVerificationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteAddressVerificationConflict creates a CompleteAddressVerificationConflict with default headers values
func NewCompleteAddressVerificationConflict() *CompleteAddressVerificationConflict {
	return &CompleteAddressVerificationConflict{}
}

/*
CompleteAddressVerificationConflict describes a response with status code 409, with default header values.

Conflict
*/
type CompleteAddressVerificationConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification conflict response has a 2xx status code
func (o *CompleteAddressVerificationConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification conflict response has a 3xx status code
func (o *CompleteAddressVerificationConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification conflict response has a 4xx status code
func (o *CompleteAddressVerificationConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification conflict response has a 5xx status code
func (o *CompleteAddressVerificationConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification conflict response a status code equal to that given
func (o *CompleteAddressVerificationConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the complete address verification conflict response
func (o *CompleteAddressVerificationConflict) Code() int {
	return 409
}

func (o *CompleteAddressVerificationConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationConflict %s", 409, payload)
}

func (o *CompleteAddressVerificationConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationConflict %s", 409, payload)
}

func (o *CompleteAddressVerificationConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteAddressVerificationPreconditionFailed creates a CompleteAddressVerificationPreconditionFailed with default headers values
func NewCompleteAddressVerificationPreconditionFailed() *CompleteAddressVerificationPreconditionFailed {
	return &CompleteAddressVerificationPreconditionFailed{}
}

/*
CompleteAddressVerificationPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type CompleteAddressVerificationPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification precondition failed response has a 2xx status code
func (o *CompleteAddressVerificationPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification precondition failed response has a 3xx status code
func (o *CompleteAddressVerificationPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification precondition failed response has a 4xx status code
func (o *CompleteAddressVerificationPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification precondition failed response has a 5xx status code
func (o *CompleteAddressVerificationPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification precondition failed response a status code equal to that given
func (o *CompleteAddressVerificationPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the complete address verification precondition failed response
func (o *CompleteAddressVerificationPreconditionFailed) Code() int {
	return 412
}

func (o *CompleteAddressVerificationPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationPreconditionFailed %s", 412, payload)
}

func (o *CompleteAddressVerificationPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationPreconditionFailed %s", 412, payload)
}

func (o *CompleteAddressVerificationPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCompleteAddressVerificationUnprocessableEntity creates a CompleteAddressVerificationUnprocessableEntity with default headers values
func NewCompleteAddressVerificationUnprocessableEntity() *CompleteAddressVerificationUnprocessableEntity {
	return &CompleteAddressVerificationUnprocessableEntity{}
}

/*
CompleteAddressVerificationUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type CompleteAddressVerificationUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this complete address verification unprocessable entity response has a 2xx status code
func (o *CompleteAddressVerificationUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this complete address verification unprocessable entity response has a 3xx status code
func (o *CompleteAddressVerificationUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this complete address verification unprocessable entity response has a 4xx status code
func (o *CompleteAddressVerificationUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this complete address verification unprocessable entity response has a 5xx status code
func (o *CompleteAddressVerificationUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this complete address verification unprocessable entity response a status code equal to that given
func (o *CompleteAddressVerificationUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the complete address verification unprocessable entity response
func (o *CompleteAddressVerificationUnprocessableEntity) Code() int {
	return 422
}

func (o *CompleteAddressVerificationUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationUnprocessableEntity %s", 422, payload)
}

func (o *CompleteAddressVerificationUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/address/verification/complete][%d] completeAddressVerificationUnprocessableEntity %s", 422, payload)
}

func (o *CompleteAddressVerificationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *CompleteAddressVerificationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
