// Code generated by go-swagger; DO NOT EDIT.

package users

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

// DeprecatedChangePasswordReader is a Reader for the DeprecatedChangePassword structure.
type DeprecatedChangePasswordReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeprecatedChangePasswordReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeprecatedChangePasswordNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeprecatedChangePasswordBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeprecatedChangePasswordUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeprecatedChangePasswordForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeprecatedChangePasswordNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewDeprecatedChangePasswordPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewDeprecatedChangePasswordUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeprecatedChangePasswordTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools/{ipID}/users/{userID}/change_password] deprecatedChangePassword", response, response.Code())
	}
}

// NewDeprecatedChangePasswordNoContent creates a DeprecatedChangePasswordNoContent with default headers values
func NewDeprecatedChangePasswordNoContent() *DeprecatedChangePasswordNoContent {
	return &DeprecatedChangePasswordNoContent{}
}

/*
DeprecatedChangePasswordNoContent describes a response with status code 204, with default header values.

Password has been changed
*/
type DeprecatedChangePasswordNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this deprecated change password no content response has a 2xx status code
func (o *DeprecatedChangePasswordNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this deprecated change password no content response has a 3xx status code
func (o *DeprecatedChangePasswordNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password no content response has a 4xx status code
func (o *DeprecatedChangePasswordNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this deprecated change password no content response has a 5xx status code
func (o *DeprecatedChangePasswordNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password no content response a status code equal to that given
func (o *DeprecatedChangePasswordNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the deprecated change password no content response
func (o *DeprecatedChangePasswordNoContent) Code() int {
	return 204
}

func (o *DeprecatedChangePasswordNoContent) Error() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordNoContent", 204)
}

func (o *DeprecatedChangePasswordNoContent) String() string {
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordNoContent", 204)
}

func (o *DeprecatedChangePasswordNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewDeprecatedChangePasswordBadRequest creates a DeprecatedChangePasswordBadRequest with default headers values
func NewDeprecatedChangePasswordBadRequest() *DeprecatedChangePasswordBadRequest {
	return &DeprecatedChangePasswordBadRequest{}
}

/*
DeprecatedChangePasswordBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type DeprecatedChangePasswordBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password bad request response has a 2xx status code
func (o *DeprecatedChangePasswordBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password bad request response has a 3xx status code
func (o *DeprecatedChangePasswordBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password bad request response has a 4xx status code
func (o *DeprecatedChangePasswordBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password bad request response has a 5xx status code
func (o *DeprecatedChangePasswordBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password bad request response a status code equal to that given
func (o *DeprecatedChangePasswordBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the deprecated change password bad request response
func (o *DeprecatedChangePasswordBadRequest) Code() int {
	return 400
}

func (o *DeprecatedChangePasswordBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordBadRequest %s", 400, payload)
}

func (o *DeprecatedChangePasswordBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordBadRequest %s", 400, payload)
}

func (o *DeprecatedChangePasswordBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordUnauthorized creates a DeprecatedChangePasswordUnauthorized with default headers values
func NewDeprecatedChangePasswordUnauthorized() *DeprecatedChangePasswordUnauthorized {
	return &DeprecatedChangePasswordUnauthorized{}
}

/*
DeprecatedChangePasswordUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeprecatedChangePasswordUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password unauthorized response has a 2xx status code
func (o *DeprecatedChangePasswordUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password unauthorized response has a 3xx status code
func (o *DeprecatedChangePasswordUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password unauthorized response has a 4xx status code
func (o *DeprecatedChangePasswordUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password unauthorized response has a 5xx status code
func (o *DeprecatedChangePasswordUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password unauthorized response a status code equal to that given
func (o *DeprecatedChangePasswordUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the deprecated change password unauthorized response
func (o *DeprecatedChangePasswordUnauthorized) Code() int {
	return 401
}

func (o *DeprecatedChangePasswordUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordUnauthorized %s", 401, payload)
}

func (o *DeprecatedChangePasswordUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordUnauthorized %s", 401, payload)
}

func (o *DeprecatedChangePasswordUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordForbidden creates a DeprecatedChangePasswordForbidden with default headers values
func NewDeprecatedChangePasswordForbidden() *DeprecatedChangePasswordForbidden {
	return &DeprecatedChangePasswordForbidden{}
}

/*
DeprecatedChangePasswordForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeprecatedChangePasswordForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password forbidden response has a 2xx status code
func (o *DeprecatedChangePasswordForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password forbidden response has a 3xx status code
func (o *DeprecatedChangePasswordForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password forbidden response has a 4xx status code
func (o *DeprecatedChangePasswordForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password forbidden response has a 5xx status code
func (o *DeprecatedChangePasswordForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password forbidden response a status code equal to that given
func (o *DeprecatedChangePasswordForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the deprecated change password forbidden response
func (o *DeprecatedChangePasswordForbidden) Code() int {
	return 403
}

func (o *DeprecatedChangePasswordForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordForbidden %s", 403, payload)
}

func (o *DeprecatedChangePasswordForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordForbidden %s", 403, payload)
}

func (o *DeprecatedChangePasswordForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordNotFound creates a DeprecatedChangePasswordNotFound with default headers values
func NewDeprecatedChangePasswordNotFound() *DeprecatedChangePasswordNotFound {
	return &DeprecatedChangePasswordNotFound{}
}

/*
DeprecatedChangePasswordNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeprecatedChangePasswordNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password not found response has a 2xx status code
func (o *DeprecatedChangePasswordNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password not found response has a 3xx status code
func (o *DeprecatedChangePasswordNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password not found response has a 4xx status code
func (o *DeprecatedChangePasswordNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password not found response has a 5xx status code
func (o *DeprecatedChangePasswordNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password not found response a status code equal to that given
func (o *DeprecatedChangePasswordNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the deprecated change password not found response
func (o *DeprecatedChangePasswordNotFound) Code() int {
	return 404
}

func (o *DeprecatedChangePasswordNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordNotFound %s", 404, payload)
}

func (o *DeprecatedChangePasswordNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordNotFound %s", 404, payload)
}

func (o *DeprecatedChangePasswordNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordPreconditionFailed creates a DeprecatedChangePasswordPreconditionFailed with default headers values
func NewDeprecatedChangePasswordPreconditionFailed() *DeprecatedChangePasswordPreconditionFailed {
	return &DeprecatedChangePasswordPreconditionFailed{}
}

/*
DeprecatedChangePasswordPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type DeprecatedChangePasswordPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password precondition failed response has a 2xx status code
func (o *DeprecatedChangePasswordPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password precondition failed response has a 3xx status code
func (o *DeprecatedChangePasswordPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password precondition failed response has a 4xx status code
func (o *DeprecatedChangePasswordPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password precondition failed response has a 5xx status code
func (o *DeprecatedChangePasswordPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password precondition failed response a status code equal to that given
func (o *DeprecatedChangePasswordPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the deprecated change password precondition failed response
func (o *DeprecatedChangePasswordPreconditionFailed) Code() int {
	return 412
}

func (o *DeprecatedChangePasswordPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordPreconditionFailed %s", 412, payload)
}

func (o *DeprecatedChangePasswordPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordPreconditionFailed %s", 412, payload)
}

func (o *DeprecatedChangePasswordPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordUnprocessableEntity creates a DeprecatedChangePasswordUnprocessableEntity with default headers values
func NewDeprecatedChangePasswordUnprocessableEntity() *DeprecatedChangePasswordUnprocessableEntity {
	return &DeprecatedChangePasswordUnprocessableEntity{}
}

/*
DeprecatedChangePasswordUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type DeprecatedChangePasswordUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password unprocessable entity response has a 2xx status code
func (o *DeprecatedChangePasswordUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password unprocessable entity response has a 3xx status code
func (o *DeprecatedChangePasswordUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password unprocessable entity response has a 4xx status code
func (o *DeprecatedChangePasswordUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password unprocessable entity response has a 5xx status code
func (o *DeprecatedChangePasswordUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password unprocessable entity response a status code equal to that given
func (o *DeprecatedChangePasswordUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the deprecated change password unprocessable entity response
func (o *DeprecatedChangePasswordUnprocessableEntity) Code() int {
	return 422
}

func (o *DeprecatedChangePasswordUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordUnprocessableEntity %s", 422, payload)
}

func (o *DeprecatedChangePasswordUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordUnprocessableEntity %s", 422, payload)
}

func (o *DeprecatedChangePasswordUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeprecatedChangePasswordTooManyRequests creates a DeprecatedChangePasswordTooManyRequests with default headers values
func NewDeprecatedChangePasswordTooManyRequests() *DeprecatedChangePasswordTooManyRequests {
	return &DeprecatedChangePasswordTooManyRequests{}
}

/*
DeprecatedChangePasswordTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeprecatedChangePasswordTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this deprecated change password too many requests response has a 2xx status code
func (o *DeprecatedChangePasswordTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this deprecated change password too many requests response has a 3xx status code
func (o *DeprecatedChangePasswordTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this deprecated change password too many requests response has a 4xx status code
func (o *DeprecatedChangePasswordTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this deprecated change password too many requests response has a 5xx status code
func (o *DeprecatedChangePasswordTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this deprecated change password too many requests response a status code equal to that given
func (o *DeprecatedChangePasswordTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the deprecated change password too many requests response
func (o *DeprecatedChangePasswordTooManyRequests) Code() int {
	return 429
}

func (o *DeprecatedChangePasswordTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordTooManyRequests %s", 429, payload)
}

func (o *DeprecatedChangePasswordTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /system/pools/{ipID}/users/{userID}/change_password][%d] deprecatedChangePasswordTooManyRequests %s", 429, payload)
}

func (o *DeprecatedChangePasswordTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeprecatedChangePasswordTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
