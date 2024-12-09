// Code generated by go-swagger; DO NOT EDIT.

package apis

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// DeleteAPIReader is a Reader for the DeleteAPI structure.
type DeleteAPIReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAPIReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteAPINoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteAPIUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteAPIForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteAPINotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteAPITooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /apis/{api}] deleteAPI", response, response.Code())
	}
}

// NewDeleteAPINoContent creates a DeleteAPINoContent with default headers values
func NewDeleteAPINoContent() *DeleteAPINoContent {
	return &DeleteAPINoContent{}
}

/*
DeleteAPINoContent describes a response with status code 204, with default header values.

	API has been deleted
*/
type DeleteAPINoContent struct {
}

// IsSuccess returns true when this delete Api no content response has a 2xx status code
func (o *DeleteAPINoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete Api no content response has a 3xx status code
func (o *DeleteAPINoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api no content response has a 4xx status code
func (o *DeleteAPINoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete Api no content response has a 5xx status code
func (o *DeleteAPINoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api no content response a status code equal to that given
func (o *DeleteAPINoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete Api no content response
func (o *DeleteAPINoContent) Code() int {
	return 204
}

func (o *DeleteAPINoContent) Error() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiNoContent ", 204)
}

func (o *DeleteAPINoContent) String() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiNoContent ", 204)
}

func (o *DeleteAPINoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteAPIUnauthorized creates a DeleteAPIUnauthorized with default headers values
func NewDeleteAPIUnauthorized() *DeleteAPIUnauthorized {
	return &DeleteAPIUnauthorized{}
}

/*
DeleteAPIUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteAPIUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete Api unauthorized response has a 2xx status code
func (o *DeleteAPIUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete Api unauthorized response has a 3xx status code
func (o *DeleteAPIUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api unauthorized response has a 4xx status code
func (o *DeleteAPIUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete Api unauthorized response has a 5xx status code
func (o *DeleteAPIUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api unauthorized response a status code equal to that given
func (o *DeleteAPIUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete Api unauthorized response
func (o *DeleteAPIUnauthorized) Code() int {
	return 401
}

func (o *DeleteAPIUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteAPIUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteAPIUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteAPIUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAPIForbidden creates a DeleteAPIForbidden with default headers values
func NewDeleteAPIForbidden() *DeleteAPIForbidden {
	return &DeleteAPIForbidden{}
}

/*
DeleteAPIForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteAPIForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete Api forbidden response has a 2xx status code
func (o *DeleteAPIForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete Api forbidden response has a 3xx status code
func (o *DeleteAPIForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api forbidden response has a 4xx status code
func (o *DeleteAPIForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete Api forbidden response has a 5xx status code
func (o *DeleteAPIForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api forbidden response a status code equal to that given
func (o *DeleteAPIForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete Api forbidden response
func (o *DeleteAPIForbidden) Code() int {
	return 403
}

func (o *DeleteAPIForbidden) Error() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiForbidden  %+v", 403, o.Payload)
}

func (o *DeleteAPIForbidden) String() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiForbidden  %+v", 403, o.Payload)
}

func (o *DeleteAPIForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteAPIForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAPINotFound creates a DeleteAPINotFound with default headers values
func NewDeleteAPINotFound() *DeleteAPINotFound {
	return &DeleteAPINotFound{}
}

/*
DeleteAPINotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteAPINotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete Api not found response has a 2xx status code
func (o *DeleteAPINotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete Api not found response has a 3xx status code
func (o *DeleteAPINotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api not found response has a 4xx status code
func (o *DeleteAPINotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete Api not found response has a 5xx status code
func (o *DeleteAPINotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api not found response a status code equal to that given
func (o *DeleteAPINotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete Api not found response
func (o *DeleteAPINotFound) Code() int {
	return 404
}

func (o *DeleteAPINotFound) Error() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiNotFound  %+v", 404, o.Payload)
}

func (o *DeleteAPINotFound) String() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiNotFound  %+v", 404, o.Payload)
}

func (o *DeleteAPINotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteAPINotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteAPITooManyRequests creates a DeleteAPITooManyRequests with default headers values
func NewDeleteAPITooManyRequests() *DeleteAPITooManyRequests {
	return &DeleteAPITooManyRequests{}
}

/*
DeleteAPITooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteAPITooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete Api too many requests response has a 2xx status code
func (o *DeleteAPITooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete Api too many requests response has a 3xx status code
func (o *DeleteAPITooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api too many requests response has a 4xx status code
func (o *DeleteAPITooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete Api too many requests response has a 5xx status code
func (o *DeleteAPITooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api too many requests response a status code equal to that given
func (o *DeleteAPITooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete Api too many requests response
func (o *DeleteAPITooManyRequests) Code() int {
	return 429
}

func (o *DeleteAPITooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteAPITooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /apis/{api}][%d] deleteApiTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteAPITooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteAPITooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
