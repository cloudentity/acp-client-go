// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// ChangeTotpSecretReader is a Reader for the ChangeTotpSecret structure.
type ChangeTotpSecretReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ChangeTotpSecretReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewChangeTotpSecretNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewChangeTotpSecretBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewChangeTotpSecretUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewChangeTotpSecretForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewChangeTotpSecretNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewChangeTotpSecretPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewChangeTotpSecretUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewChangeTotpSecretTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/users/{userID}/totp/change] changeTotpSecret", response, response.Code())
	}
}

// NewChangeTotpSecretNoContent creates a ChangeTotpSecretNoContent with default headers values
func NewChangeTotpSecretNoContent() *ChangeTotpSecretNoContent {
	return &ChangeTotpSecretNoContent{}
}

/*
ChangeTotpSecretNoContent describes a response with status code 204, with default header values.

	Totp secret changed
*/
type ChangeTotpSecretNoContent struct {
}

// IsSuccess returns true when this change totp secret no content response has a 2xx status code
func (o *ChangeTotpSecretNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this change totp secret no content response has a 3xx status code
func (o *ChangeTotpSecretNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret no content response has a 4xx status code
func (o *ChangeTotpSecretNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this change totp secret no content response has a 5xx status code
func (o *ChangeTotpSecretNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret no content response a status code equal to that given
func (o *ChangeTotpSecretNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the change totp secret no content response
func (o *ChangeTotpSecretNoContent) Code() int {
	return 204
}

func (o *ChangeTotpSecretNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretNoContent ", 204)
}

func (o *ChangeTotpSecretNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretNoContent ", 204)
}

func (o *ChangeTotpSecretNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewChangeTotpSecretBadRequest creates a ChangeTotpSecretBadRequest with default headers values
func NewChangeTotpSecretBadRequest() *ChangeTotpSecretBadRequest {
	return &ChangeTotpSecretBadRequest{}
}

/*
ChangeTotpSecretBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ChangeTotpSecretBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret bad request response has a 2xx status code
func (o *ChangeTotpSecretBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret bad request response has a 3xx status code
func (o *ChangeTotpSecretBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret bad request response has a 4xx status code
func (o *ChangeTotpSecretBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret bad request response has a 5xx status code
func (o *ChangeTotpSecretBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret bad request response a status code equal to that given
func (o *ChangeTotpSecretBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the change totp secret bad request response
func (o *ChangeTotpSecretBadRequest) Code() int {
	return 400
}

func (o *ChangeTotpSecretBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretBadRequest  %+v", 400, o.Payload)
}

func (o *ChangeTotpSecretBadRequest) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretBadRequest  %+v", 400, o.Payload)
}

func (o *ChangeTotpSecretBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretUnauthorized creates a ChangeTotpSecretUnauthorized with default headers values
func NewChangeTotpSecretUnauthorized() *ChangeTotpSecretUnauthorized {
	return &ChangeTotpSecretUnauthorized{}
}

/*
ChangeTotpSecretUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ChangeTotpSecretUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret unauthorized response has a 2xx status code
func (o *ChangeTotpSecretUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret unauthorized response has a 3xx status code
func (o *ChangeTotpSecretUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret unauthorized response has a 4xx status code
func (o *ChangeTotpSecretUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret unauthorized response has a 5xx status code
func (o *ChangeTotpSecretUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret unauthorized response a status code equal to that given
func (o *ChangeTotpSecretUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the change totp secret unauthorized response
func (o *ChangeTotpSecretUnauthorized) Code() int {
	return 401
}

func (o *ChangeTotpSecretUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretUnauthorized  %+v", 401, o.Payload)
}

func (o *ChangeTotpSecretUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretUnauthorized  %+v", 401, o.Payload)
}

func (o *ChangeTotpSecretUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretForbidden creates a ChangeTotpSecretForbidden with default headers values
func NewChangeTotpSecretForbidden() *ChangeTotpSecretForbidden {
	return &ChangeTotpSecretForbidden{}
}

/*
ChangeTotpSecretForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ChangeTotpSecretForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret forbidden response has a 2xx status code
func (o *ChangeTotpSecretForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret forbidden response has a 3xx status code
func (o *ChangeTotpSecretForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret forbidden response has a 4xx status code
func (o *ChangeTotpSecretForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret forbidden response has a 5xx status code
func (o *ChangeTotpSecretForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret forbidden response a status code equal to that given
func (o *ChangeTotpSecretForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the change totp secret forbidden response
func (o *ChangeTotpSecretForbidden) Code() int {
	return 403
}

func (o *ChangeTotpSecretForbidden) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretForbidden  %+v", 403, o.Payload)
}

func (o *ChangeTotpSecretForbidden) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretForbidden  %+v", 403, o.Payload)
}

func (o *ChangeTotpSecretForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretNotFound creates a ChangeTotpSecretNotFound with default headers values
func NewChangeTotpSecretNotFound() *ChangeTotpSecretNotFound {
	return &ChangeTotpSecretNotFound{}
}

/*
ChangeTotpSecretNotFound describes a response with status code 404, with default header values.

Not found
*/
type ChangeTotpSecretNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret not found response has a 2xx status code
func (o *ChangeTotpSecretNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret not found response has a 3xx status code
func (o *ChangeTotpSecretNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret not found response has a 4xx status code
func (o *ChangeTotpSecretNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret not found response has a 5xx status code
func (o *ChangeTotpSecretNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret not found response a status code equal to that given
func (o *ChangeTotpSecretNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the change totp secret not found response
func (o *ChangeTotpSecretNotFound) Code() int {
	return 404
}

func (o *ChangeTotpSecretNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretNotFound  %+v", 404, o.Payload)
}

func (o *ChangeTotpSecretNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretNotFound  %+v", 404, o.Payload)
}

func (o *ChangeTotpSecretNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretPreconditionFailed creates a ChangeTotpSecretPreconditionFailed with default headers values
func NewChangeTotpSecretPreconditionFailed() *ChangeTotpSecretPreconditionFailed {
	return &ChangeTotpSecretPreconditionFailed{}
}

/*
ChangeTotpSecretPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type ChangeTotpSecretPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret precondition failed response has a 2xx status code
func (o *ChangeTotpSecretPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret precondition failed response has a 3xx status code
func (o *ChangeTotpSecretPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret precondition failed response has a 4xx status code
func (o *ChangeTotpSecretPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret precondition failed response has a 5xx status code
func (o *ChangeTotpSecretPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret precondition failed response a status code equal to that given
func (o *ChangeTotpSecretPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the change totp secret precondition failed response
func (o *ChangeTotpSecretPreconditionFailed) Code() int {
	return 412
}

func (o *ChangeTotpSecretPreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretPreconditionFailed  %+v", 412, o.Payload)
}

func (o *ChangeTotpSecretPreconditionFailed) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretPreconditionFailed  %+v", 412, o.Payload)
}

func (o *ChangeTotpSecretPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretUnprocessableEntity creates a ChangeTotpSecretUnprocessableEntity with default headers values
func NewChangeTotpSecretUnprocessableEntity() *ChangeTotpSecretUnprocessableEntity {
	return &ChangeTotpSecretUnprocessableEntity{}
}

/*
ChangeTotpSecretUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type ChangeTotpSecretUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret unprocessable entity response has a 2xx status code
func (o *ChangeTotpSecretUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret unprocessable entity response has a 3xx status code
func (o *ChangeTotpSecretUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret unprocessable entity response has a 4xx status code
func (o *ChangeTotpSecretUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret unprocessable entity response has a 5xx status code
func (o *ChangeTotpSecretUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret unprocessable entity response a status code equal to that given
func (o *ChangeTotpSecretUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the change totp secret unprocessable entity response
func (o *ChangeTotpSecretUnprocessableEntity) Code() int {
	return 422
}

func (o *ChangeTotpSecretUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ChangeTotpSecretUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ChangeTotpSecretUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewChangeTotpSecretTooManyRequests creates a ChangeTotpSecretTooManyRequests with default headers values
func NewChangeTotpSecretTooManyRequests() *ChangeTotpSecretTooManyRequests {
	return &ChangeTotpSecretTooManyRequests{}
}

/*
ChangeTotpSecretTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ChangeTotpSecretTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this change totp secret too many requests response has a 2xx status code
func (o *ChangeTotpSecretTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this change totp secret too many requests response has a 3xx status code
func (o *ChangeTotpSecretTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this change totp secret too many requests response has a 4xx status code
func (o *ChangeTotpSecretTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this change totp secret too many requests response has a 5xx status code
func (o *ChangeTotpSecretTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this change totp secret too many requests response a status code equal to that given
func (o *ChangeTotpSecretTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the change totp secret too many requests response
func (o *ChangeTotpSecretTooManyRequests) Code() int {
	return 429
}

func (o *ChangeTotpSecretTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretTooManyRequests  %+v", 429, o.Payload)
}

func (o *ChangeTotpSecretTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/totp/change][%d] changeTotpSecretTooManyRequests  %+v", 429, o.Payload)
}

func (o *ChangeTotpSecretTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ChangeTotpSecretTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}