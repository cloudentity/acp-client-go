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

// DeleteConsentActionReader is a Reader for the DeleteConsentAction structure.
type DeleteConsentActionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteConsentActionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteConsentActionNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteConsentActionUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteConsentActionForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteConsentActionNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteConsentActionTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteConsentActionNoContent creates a DeleteConsentActionNoContent with default headers values
func NewDeleteConsentActionNoContent() *DeleteConsentActionNoContent {
	return &DeleteConsentActionNoContent{}
}

/*
DeleteConsentActionNoContent describes a response with status code 204, with default header values.

	ConsentAction has been deleted
*/
type DeleteConsentActionNoContent struct {
}

// IsSuccess returns true when this delete consent action no content response has a 2xx status code
func (o *DeleteConsentActionNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete consent action no content response has a 3xx status code
func (o *DeleteConsentActionNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete consent action no content response has a 4xx status code
func (o *DeleteConsentActionNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete consent action no content response has a 5xx status code
func (o *DeleteConsentActionNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete consent action no content response a status code equal to that given
func (o *DeleteConsentActionNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *DeleteConsentActionNoContent) Error() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionNoContent ", 204)
}

func (o *DeleteConsentActionNoContent) String() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionNoContent ", 204)
}

func (o *DeleteConsentActionNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteConsentActionUnauthorized creates a DeleteConsentActionUnauthorized with default headers values
func NewDeleteConsentActionUnauthorized() *DeleteConsentActionUnauthorized {
	return &DeleteConsentActionUnauthorized{}
}

/*
DeleteConsentActionUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type DeleteConsentActionUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete consent action unauthorized response has a 2xx status code
func (o *DeleteConsentActionUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete consent action unauthorized response has a 3xx status code
func (o *DeleteConsentActionUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete consent action unauthorized response has a 4xx status code
func (o *DeleteConsentActionUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete consent action unauthorized response has a 5xx status code
func (o *DeleteConsentActionUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete consent action unauthorized response a status code equal to that given
func (o *DeleteConsentActionUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *DeleteConsentActionUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteConsentActionUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteConsentActionUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteConsentActionUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConsentActionForbidden creates a DeleteConsentActionForbidden with default headers values
func NewDeleteConsentActionForbidden() *DeleteConsentActionForbidden {
	return &DeleteConsentActionForbidden{}
}

/*
DeleteConsentActionForbidden describes a response with status code 403, with default header values.

HttpError
*/
type DeleteConsentActionForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete consent action forbidden response has a 2xx status code
func (o *DeleteConsentActionForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete consent action forbidden response has a 3xx status code
func (o *DeleteConsentActionForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete consent action forbidden response has a 4xx status code
func (o *DeleteConsentActionForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete consent action forbidden response has a 5xx status code
func (o *DeleteConsentActionForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete consent action forbidden response a status code equal to that given
func (o *DeleteConsentActionForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *DeleteConsentActionForbidden) Error() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionForbidden  %+v", 403, o.Payload)
}

func (o *DeleteConsentActionForbidden) String() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionForbidden  %+v", 403, o.Payload)
}

func (o *DeleteConsentActionForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteConsentActionForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConsentActionNotFound creates a DeleteConsentActionNotFound with default headers values
func NewDeleteConsentActionNotFound() *DeleteConsentActionNotFound {
	return &DeleteConsentActionNotFound{}
}

/*
DeleteConsentActionNotFound describes a response with status code 404, with default header values.

HttpError
*/
type DeleteConsentActionNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete consent action not found response has a 2xx status code
func (o *DeleteConsentActionNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete consent action not found response has a 3xx status code
func (o *DeleteConsentActionNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete consent action not found response has a 4xx status code
func (o *DeleteConsentActionNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete consent action not found response has a 5xx status code
func (o *DeleteConsentActionNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete consent action not found response a status code equal to that given
func (o *DeleteConsentActionNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *DeleteConsentActionNotFound) Error() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionNotFound  %+v", 404, o.Payload)
}

func (o *DeleteConsentActionNotFound) String() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionNotFound  %+v", 404, o.Payload)
}

func (o *DeleteConsentActionNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteConsentActionNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteConsentActionTooManyRequests creates a DeleteConsentActionTooManyRequests with default headers values
func NewDeleteConsentActionTooManyRequests() *DeleteConsentActionTooManyRequests {
	return &DeleteConsentActionTooManyRequests{}
}

/*
DeleteConsentActionTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type DeleteConsentActionTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete consent action too many requests response has a 2xx status code
func (o *DeleteConsentActionTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete consent action too many requests response has a 3xx status code
func (o *DeleteConsentActionTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete consent action too many requests response has a 4xx status code
func (o *DeleteConsentActionTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete consent action too many requests response has a 5xx status code
func (o *DeleteConsentActionTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete consent action too many requests response a status code equal to that given
func (o *DeleteConsentActionTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *DeleteConsentActionTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteConsentActionTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /actions/{action}][%d] deleteConsentActionTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteConsentActionTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteConsentActionTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
