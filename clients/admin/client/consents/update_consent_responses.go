// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UpdateConsentReader is a Reader for the UpdateConsent structure.
type UpdateConsentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateConsentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewUpdateConsentCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUpdateConsentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateConsentForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateConsentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewUpdateConsentConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUpdateConsentUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateConsentTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /consents/{consent}] updateConsent", response, response.Code())
	}
}

// NewUpdateConsentCreated creates a UpdateConsentCreated with default headers values
func NewUpdateConsentCreated() *UpdateConsentCreated {
	return &UpdateConsentCreated{}
}

/*
UpdateConsentCreated describes a response with status code 201, with default header values.

Consent
*/
type UpdateConsentCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Consent
}

// IsSuccess returns true when this update consent created response has a 2xx status code
func (o *UpdateConsentCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update consent created response has a 3xx status code
func (o *UpdateConsentCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent created response has a 4xx status code
func (o *UpdateConsentCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this update consent created response has a 5xx status code
func (o *UpdateConsentCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent created response a status code equal to that given
func (o *UpdateConsentCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the update consent created response
func (o *UpdateConsentCreated) Code() int {
	return 201
}

func (o *UpdateConsentCreated) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentCreated  %+v", 201, o.Payload)
}

func (o *UpdateConsentCreated) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentCreated  %+v", 201, o.Payload)
}

func (o *UpdateConsentCreated) GetPayload() *models.Consent {
	return o.Payload
}

func (o *UpdateConsentCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Consent)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentUnauthorized creates a UpdateConsentUnauthorized with default headers values
func NewUpdateConsentUnauthorized() *UpdateConsentUnauthorized {
	return &UpdateConsentUnauthorized{}
}

/*
UpdateConsentUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateConsentUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent unauthorized response has a 2xx status code
func (o *UpdateConsentUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent unauthorized response has a 3xx status code
func (o *UpdateConsentUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent unauthorized response has a 4xx status code
func (o *UpdateConsentUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent unauthorized response has a 5xx status code
func (o *UpdateConsentUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent unauthorized response a status code equal to that given
func (o *UpdateConsentUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update consent unauthorized response
func (o *UpdateConsentUnauthorized) Code() int {
	return 401
}

func (o *UpdateConsentUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateConsentUnauthorized) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentUnauthorized  %+v", 401, o.Payload)
}

func (o *UpdateConsentUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentForbidden creates a UpdateConsentForbidden with default headers values
func NewUpdateConsentForbidden() *UpdateConsentForbidden {
	return &UpdateConsentForbidden{}
}

/*
UpdateConsentForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateConsentForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent forbidden response has a 2xx status code
func (o *UpdateConsentForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent forbidden response has a 3xx status code
func (o *UpdateConsentForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent forbidden response has a 4xx status code
func (o *UpdateConsentForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent forbidden response has a 5xx status code
func (o *UpdateConsentForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent forbidden response a status code equal to that given
func (o *UpdateConsentForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update consent forbidden response
func (o *UpdateConsentForbidden) Code() int {
	return 403
}

func (o *UpdateConsentForbidden) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentForbidden  %+v", 403, o.Payload)
}

func (o *UpdateConsentForbidden) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentForbidden  %+v", 403, o.Payload)
}

func (o *UpdateConsentForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentNotFound creates a UpdateConsentNotFound with default headers values
func NewUpdateConsentNotFound() *UpdateConsentNotFound {
	return &UpdateConsentNotFound{}
}

/*
UpdateConsentNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateConsentNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent not found response has a 2xx status code
func (o *UpdateConsentNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent not found response has a 3xx status code
func (o *UpdateConsentNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent not found response has a 4xx status code
func (o *UpdateConsentNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent not found response has a 5xx status code
func (o *UpdateConsentNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent not found response a status code equal to that given
func (o *UpdateConsentNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update consent not found response
func (o *UpdateConsentNotFound) Code() int {
	return 404
}

func (o *UpdateConsentNotFound) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentNotFound  %+v", 404, o.Payload)
}

func (o *UpdateConsentNotFound) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentNotFound  %+v", 404, o.Payload)
}

func (o *UpdateConsentNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentConflict creates a UpdateConsentConflict with default headers values
func NewUpdateConsentConflict() *UpdateConsentConflict {
	return &UpdateConsentConflict{}
}

/*
UpdateConsentConflict describes a response with status code 409, with default header values.

Conflict
*/
type UpdateConsentConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent conflict response has a 2xx status code
func (o *UpdateConsentConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent conflict response has a 3xx status code
func (o *UpdateConsentConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent conflict response has a 4xx status code
func (o *UpdateConsentConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent conflict response has a 5xx status code
func (o *UpdateConsentConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent conflict response a status code equal to that given
func (o *UpdateConsentConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the update consent conflict response
func (o *UpdateConsentConflict) Code() int {
	return 409
}

func (o *UpdateConsentConflict) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentConflict  %+v", 409, o.Payload)
}

func (o *UpdateConsentConflict) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentConflict  %+v", 409, o.Payload)
}

func (o *UpdateConsentConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentUnprocessableEntity creates a UpdateConsentUnprocessableEntity with default headers values
func NewUpdateConsentUnprocessableEntity() *UpdateConsentUnprocessableEntity {
	return &UpdateConsentUnprocessableEntity{}
}

/*
UpdateConsentUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UpdateConsentUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent unprocessable entity response has a 2xx status code
func (o *UpdateConsentUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent unprocessable entity response has a 3xx status code
func (o *UpdateConsentUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent unprocessable entity response has a 4xx status code
func (o *UpdateConsentUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent unprocessable entity response has a 5xx status code
func (o *UpdateConsentUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent unprocessable entity response a status code equal to that given
func (o *UpdateConsentUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the update consent unprocessable entity response
func (o *UpdateConsentUnprocessableEntity) Code() int {
	return 422
}

func (o *UpdateConsentUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateConsentUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UpdateConsentUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConsentTooManyRequests creates a UpdateConsentTooManyRequests with default headers values
func NewUpdateConsentTooManyRequests() *UpdateConsentTooManyRequests {
	return &UpdateConsentTooManyRequests{}
}

/*
UpdateConsentTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateConsentTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update consent too many requests response has a 2xx status code
func (o *UpdateConsentTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update consent too many requests response has a 3xx status code
func (o *UpdateConsentTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update consent too many requests response has a 4xx status code
func (o *UpdateConsentTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update consent too many requests response has a 5xx status code
func (o *UpdateConsentTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update consent too many requests response a status code equal to that given
func (o *UpdateConsentTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update consent too many requests response
func (o *UpdateConsentTooManyRequests) Code() int {
	return 429
}

func (o *UpdateConsentTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateConsentTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /consents/{consent}][%d] updateConsentTooManyRequests  %+v", 429, o.Payload)
}

func (o *UpdateConsentTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateConsentTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
