// Code generated by go-swagger; DO NOT EDIT.

package translations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// DeleteTranslationReader is a Reader for the DeleteTranslation structure.
type DeleteTranslationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteTranslationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteTranslationNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteTranslationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteTranslationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteTranslationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteTranslationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /translation/{locale}] deleteTranslation", response, response.Code())
	}
}

// NewDeleteTranslationNoContent creates a DeleteTranslationNoContent with default headers values
func NewDeleteTranslationNoContent() *DeleteTranslationNoContent {
	return &DeleteTranslationNoContent{}
}

/*
DeleteTranslationNoContent describes a response with status code 204, with default header values.

	translation has been deleted
*/
type DeleteTranslationNoContent struct {
}

// IsSuccess returns true when this delete translation no content response has a 2xx status code
func (o *DeleteTranslationNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete translation no content response has a 3xx status code
func (o *DeleteTranslationNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete translation no content response has a 4xx status code
func (o *DeleteTranslationNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete translation no content response has a 5xx status code
func (o *DeleteTranslationNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete translation no content response a status code equal to that given
func (o *DeleteTranslationNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete translation no content response
func (o *DeleteTranslationNoContent) Code() int {
	return 204
}

func (o *DeleteTranslationNoContent) Error() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationNoContent ", 204)
}

func (o *DeleteTranslationNoContent) String() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationNoContent ", 204)
}

func (o *DeleteTranslationNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteTranslationUnauthorized creates a DeleteTranslationUnauthorized with default headers values
func NewDeleteTranslationUnauthorized() *DeleteTranslationUnauthorized {
	return &DeleteTranslationUnauthorized{}
}

/*
DeleteTranslationUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteTranslationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete translation unauthorized response has a 2xx status code
func (o *DeleteTranslationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete translation unauthorized response has a 3xx status code
func (o *DeleteTranslationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete translation unauthorized response has a 4xx status code
func (o *DeleteTranslationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete translation unauthorized response has a 5xx status code
func (o *DeleteTranslationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete translation unauthorized response a status code equal to that given
func (o *DeleteTranslationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete translation unauthorized response
func (o *DeleteTranslationUnauthorized) Code() int {
	return 401
}

func (o *DeleteTranslationUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteTranslationUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteTranslationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteTranslationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTranslationForbidden creates a DeleteTranslationForbidden with default headers values
func NewDeleteTranslationForbidden() *DeleteTranslationForbidden {
	return &DeleteTranslationForbidden{}
}

/*
DeleteTranslationForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteTranslationForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete translation forbidden response has a 2xx status code
func (o *DeleteTranslationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete translation forbidden response has a 3xx status code
func (o *DeleteTranslationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete translation forbidden response has a 4xx status code
func (o *DeleteTranslationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete translation forbidden response has a 5xx status code
func (o *DeleteTranslationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete translation forbidden response a status code equal to that given
func (o *DeleteTranslationForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete translation forbidden response
func (o *DeleteTranslationForbidden) Code() int {
	return 403
}

func (o *DeleteTranslationForbidden) Error() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationForbidden  %+v", 403, o.Payload)
}

func (o *DeleteTranslationForbidden) String() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationForbidden  %+v", 403, o.Payload)
}

func (o *DeleteTranslationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteTranslationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTranslationNotFound creates a DeleteTranslationNotFound with default headers values
func NewDeleteTranslationNotFound() *DeleteTranslationNotFound {
	return &DeleteTranslationNotFound{}
}

/*
DeleteTranslationNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteTranslationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete translation not found response has a 2xx status code
func (o *DeleteTranslationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete translation not found response has a 3xx status code
func (o *DeleteTranslationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete translation not found response has a 4xx status code
func (o *DeleteTranslationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete translation not found response has a 5xx status code
func (o *DeleteTranslationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete translation not found response a status code equal to that given
func (o *DeleteTranslationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete translation not found response
func (o *DeleteTranslationNotFound) Code() int {
	return 404
}

func (o *DeleteTranslationNotFound) Error() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationNotFound  %+v", 404, o.Payload)
}

func (o *DeleteTranslationNotFound) String() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationNotFound  %+v", 404, o.Payload)
}

func (o *DeleteTranslationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteTranslationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTranslationTooManyRequests creates a DeleteTranslationTooManyRequests with default headers values
func NewDeleteTranslationTooManyRequests() *DeleteTranslationTooManyRequests {
	return &DeleteTranslationTooManyRequests{}
}

/*
DeleteTranslationTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteTranslationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete translation too many requests response has a 2xx status code
func (o *DeleteTranslationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete translation too many requests response has a 3xx status code
func (o *DeleteTranslationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete translation too many requests response has a 4xx status code
func (o *DeleteTranslationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete translation too many requests response has a 5xx status code
func (o *DeleteTranslationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete translation too many requests response a status code equal to that given
func (o *DeleteTranslationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete translation too many requests response
func (o *DeleteTranslationTooManyRequests) Code() int {
	return 429
}

func (o *DeleteTranslationTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteTranslationTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /translation/{locale}][%d] deleteTranslationTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteTranslationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteTranslationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
