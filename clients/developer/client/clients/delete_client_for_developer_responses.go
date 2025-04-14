// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/developer/models"
)

// DeleteClientForDeveloperReader is a Reader for the DeleteClientForDeveloper structure.
type DeleteClientForDeveloperReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteClientForDeveloperReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteClientForDeveloperNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteClientForDeveloperBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteClientForDeveloperUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteClientForDeveloperForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteClientForDeveloperNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteClientForDeveloperTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /clients/{cid}] deleteClientForDeveloper", response, response.Code())
	}
}

// NewDeleteClientForDeveloperNoContent creates a DeleteClientForDeveloperNoContent with default headers values
func NewDeleteClientForDeveloperNoContent() *DeleteClientForDeveloperNoContent {
	return &DeleteClientForDeveloperNoContent{}
}

/*
DeleteClientForDeveloperNoContent describes a response with status code 204, with default header values.

	Client has been deleted
*/
type DeleteClientForDeveloperNoContent struct {
}

// IsSuccess returns true when this delete client for developer no content response has a 2xx status code
func (o *DeleteClientForDeveloperNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete client for developer no content response has a 3xx status code
func (o *DeleteClientForDeveloperNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer no content response has a 4xx status code
func (o *DeleteClientForDeveloperNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete client for developer no content response has a 5xx status code
func (o *DeleteClientForDeveloperNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer no content response a status code equal to that given
func (o *DeleteClientForDeveloperNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete client for developer no content response
func (o *DeleteClientForDeveloperNoContent) Code() int {
	return 204
}

func (o *DeleteClientForDeveloperNoContent) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperNoContent ", 204)
}

func (o *DeleteClientForDeveloperNoContent) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperNoContent ", 204)
}

func (o *DeleteClientForDeveloperNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteClientForDeveloperBadRequest creates a DeleteClientForDeveloperBadRequest with default headers values
func NewDeleteClientForDeveloperBadRequest() *DeleteClientForDeveloperBadRequest {
	return &DeleteClientForDeveloperBadRequest{}
}

/*
DeleteClientForDeveloperBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type DeleteClientForDeveloperBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete client for developer bad request response has a 2xx status code
func (o *DeleteClientForDeveloperBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete client for developer bad request response has a 3xx status code
func (o *DeleteClientForDeveloperBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer bad request response has a 4xx status code
func (o *DeleteClientForDeveloperBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete client for developer bad request response has a 5xx status code
func (o *DeleteClientForDeveloperBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer bad request response a status code equal to that given
func (o *DeleteClientForDeveloperBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete client for developer bad request response
func (o *DeleteClientForDeveloperBadRequest) Code() int {
	return 400
}

func (o *DeleteClientForDeveloperBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteClientForDeveloperBadRequest) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteClientForDeveloperBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClientForDeveloperBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClientForDeveloperUnauthorized creates a DeleteClientForDeveloperUnauthorized with default headers values
func NewDeleteClientForDeveloperUnauthorized() *DeleteClientForDeveloperUnauthorized {
	return &DeleteClientForDeveloperUnauthorized{}
}

/*
DeleteClientForDeveloperUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteClientForDeveloperUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete client for developer unauthorized response has a 2xx status code
func (o *DeleteClientForDeveloperUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete client for developer unauthorized response has a 3xx status code
func (o *DeleteClientForDeveloperUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer unauthorized response has a 4xx status code
func (o *DeleteClientForDeveloperUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete client for developer unauthorized response has a 5xx status code
func (o *DeleteClientForDeveloperUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer unauthorized response a status code equal to that given
func (o *DeleteClientForDeveloperUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete client for developer unauthorized response
func (o *DeleteClientForDeveloperUnauthorized) Code() int {
	return 401
}

func (o *DeleteClientForDeveloperUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteClientForDeveloperUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteClientForDeveloperUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClientForDeveloperUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClientForDeveloperForbidden creates a DeleteClientForDeveloperForbidden with default headers values
func NewDeleteClientForDeveloperForbidden() *DeleteClientForDeveloperForbidden {
	return &DeleteClientForDeveloperForbidden{}
}

/*
DeleteClientForDeveloperForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteClientForDeveloperForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete client for developer forbidden response has a 2xx status code
func (o *DeleteClientForDeveloperForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete client for developer forbidden response has a 3xx status code
func (o *DeleteClientForDeveloperForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer forbidden response has a 4xx status code
func (o *DeleteClientForDeveloperForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete client for developer forbidden response has a 5xx status code
func (o *DeleteClientForDeveloperForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer forbidden response a status code equal to that given
func (o *DeleteClientForDeveloperForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete client for developer forbidden response
func (o *DeleteClientForDeveloperForbidden) Code() int {
	return 403
}

func (o *DeleteClientForDeveloperForbidden) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperForbidden  %+v", 403, o.Payload)
}

func (o *DeleteClientForDeveloperForbidden) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperForbidden  %+v", 403, o.Payload)
}

func (o *DeleteClientForDeveloperForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClientForDeveloperForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClientForDeveloperNotFound creates a DeleteClientForDeveloperNotFound with default headers values
func NewDeleteClientForDeveloperNotFound() *DeleteClientForDeveloperNotFound {
	return &DeleteClientForDeveloperNotFound{}
}

/*
DeleteClientForDeveloperNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteClientForDeveloperNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete client for developer not found response has a 2xx status code
func (o *DeleteClientForDeveloperNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete client for developer not found response has a 3xx status code
func (o *DeleteClientForDeveloperNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer not found response has a 4xx status code
func (o *DeleteClientForDeveloperNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete client for developer not found response has a 5xx status code
func (o *DeleteClientForDeveloperNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer not found response a status code equal to that given
func (o *DeleteClientForDeveloperNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete client for developer not found response
func (o *DeleteClientForDeveloperNotFound) Code() int {
	return 404
}

func (o *DeleteClientForDeveloperNotFound) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperNotFound  %+v", 404, o.Payload)
}

func (o *DeleteClientForDeveloperNotFound) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperNotFound  %+v", 404, o.Payload)
}

func (o *DeleteClientForDeveloperNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClientForDeveloperNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClientForDeveloperTooManyRequests creates a DeleteClientForDeveloperTooManyRequests with default headers values
func NewDeleteClientForDeveloperTooManyRequests() *DeleteClientForDeveloperTooManyRequests {
	return &DeleteClientForDeveloperTooManyRequests{}
}

/*
DeleteClientForDeveloperTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteClientForDeveloperTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete client for developer too many requests response has a 2xx status code
func (o *DeleteClientForDeveloperTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete client for developer too many requests response has a 3xx status code
func (o *DeleteClientForDeveloperTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete client for developer too many requests response has a 4xx status code
func (o *DeleteClientForDeveloperTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete client for developer too many requests response has a 5xx status code
func (o *DeleteClientForDeveloperTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete client for developer too many requests response a status code equal to that given
func (o *DeleteClientForDeveloperTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete client for developer too many requests response
func (o *DeleteClientForDeveloperTooManyRequests) Code() int {
	return 429
}

func (o *DeleteClientForDeveloperTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteClientForDeveloperTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /clients/{cid}][%d] deleteClientForDeveloperTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteClientForDeveloperTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClientForDeveloperTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
