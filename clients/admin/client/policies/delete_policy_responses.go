// Code generated by go-swagger; DO NOT EDIT.

package policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// DeletePolicyReader is a Reader for the DeletePolicy structure.
type DeletePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeletePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeletePolicyNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeletePolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeletePolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeletePolicyForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeletePolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeletePolicyTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /policies/{pid}] deletePolicy", response, response.Code())
	}
}

// NewDeletePolicyNoContent creates a DeletePolicyNoContent with default headers values
func NewDeletePolicyNoContent() *DeletePolicyNoContent {
	return &DeletePolicyNoContent{}
}

/*
DeletePolicyNoContent describes a response with status code 204, with default header values.

	Policy has been deleted
*/
type DeletePolicyNoContent struct {
}

// IsSuccess returns true when this delete policy no content response has a 2xx status code
func (o *DeletePolicyNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete policy no content response has a 3xx status code
func (o *DeletePolicyNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy no content response has a 4xx status code
func (o *DeletePolicyNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete policy no content response has a 5xx status code
func (o *DeletePolicyNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy no content response a status code equal to that given
func (o *DeletePolicyNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete policy no content response
func (o *DeletePolicyNoContent) Code() int {
	return 204
}

func (o *DeletePolicyNoContent) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyNoContent ", 204)
}

func (o *DeletePolicyNoContent) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyNoContent ", 204)
}

func (o *DeletePolicyNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeletePolicyBadRequest creates a DeletePolicyBadRequest with default headers values
func NewDeletePolicyBadRequest() *DeletePolicyBadRequest {
	return &DeletePolicyBadRequest{}
}

/*
DeletePolicyBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type DeletePolicyBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete policy bad request response has a 2xx status code
func (o *DeletePolicyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policy bad request response has a 3xx status code
func (o *DeletePolicyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy bad request response has a 4xx status code
func (o *DeletePolicyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policy bad request response has a 5xx status code
func (o *DeletePolicyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy bad request response a status code equal to that given
func (o *DeletePolicyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete policy bad request response
func (o *DeletePolicyBadRequest) Code() int {
	return 400
}

func (o *DeletePolicyBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyBadRequest  %+v", 400, o.Payload)
}

func (o *DeletePolicyBadRequest) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyBadRequest  %+v", 400, o.Payload)
}

func (o *DeletePolicyBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePolicyUnauthorized creates a DeletePolicyUnauthorized with default headers values
func NewDeletePolicyUnauthorized() *DeletePolicyUnauthorized {
	return &DeletePolicyUnauthorized{}
}

/*
DeletePolicyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeletePolicyUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete policy unauthorized response has a 2xx status code
func (o *DeletePolicyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policy unauthorized response has a 3xx status code
func (o *DeletePolicyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy unauthorized response has a 4xx status code
func (o *DeletePolicyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policy unauthorized response has a 5xx status code
func (o *DeletePolicyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy unauthorized response a status code equal to that given
func (o *DeletePolicyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete policy unauthorized response
func (o *DeletePolicyUnauthorized) Code() int {
	return 401
}

func (o *DeletePolicyUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *DeletePolicyUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *DeletePolicyUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePolicyForbidden creates a DeletePolicyForbidden with default headers values
func NewDeletePolicyForbidden() *DeletePolicyForbidden {
	return &DeletePolicyForbidden{}
}

/*
DeletePolicyForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeletePolicyForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete policy forbidden response has a 2xx status code
func (o *DeletePolicyForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policy forbidden response has a 3xx status code
func (o *DeletePolicyForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy forbidden response has a 4xx status code
func (o *DeletePolicyForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policy forbidden response has a 5xx status code
func (o *DeletePolicyForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy forbidden response a status code equal to that given
func (o *DeletePolicyForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete policy forbidden response
func (o *DeletePolicyForbidden) Code() int {
	return 403
}

func (o *DeletePolicyForbidden) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyForbidden  %+v", 403, o.Payload)
}

func (o *DeletePolicyForbidden) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyForbidden  %+v", 403, o.Payload)
}

func (o *DeletePolicyForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePolicyForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePolicyNotFound creates a DeletePolicyNotFound with default headers values
func NewDeletePolicyNotFound() *DeletePolicyNotFound {
	return &DeletePolicyNotFound{}
}

/*
DeletePolicyNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeletePolicyNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete policy not found response has a 2xx status code
func (o *DeletePolicyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policy not found response has a 3xx status code
func (o *DeletePolicyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy not found response has a 4xx status code
func (o *DeletePolicyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policy not found response has a 5xx status code
func (o *DeletePolicyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy not found response a status code equal to that given
func (o *DeletePolicyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete policy not found response
func (o *DeletePolicyNotFound) Code() int {
	return 404
}

func (o *DeletePolicyNotFound) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyNotFound  %+v", 404, o.Payload)
}

func (o *DeletePolicyNotFound) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyNotFound  %+v", 404, o.Payload)
}

func (o *DeletePolicyNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePolicyTooManyRequests creates a DeletePolicyTooManyRequests with default headers values
func NewDeletePolicyTooManyRequests() *DeletePolicyTooManyRequests {
	return &DeletePolicyTooManyRequests{}
}

/*
DeletePolicyTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeletePolicyTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete policy too many requests response has a 2xx status code
func (o *DeletePolicyTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete policy too many requests response has a 3xx status code
func (o *DeletePolicyTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete policy too many requests response has a 4xx status code
func (o *DeletePolicyTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete policy too many requests response has a 5xx status code
func (o *DeletePolicyTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete policy too many requests response a status code equal to that given
func (o *DeletePolicyTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete policy too many requests response
func (o *DeletePolicyTooManyRequests) Code() int {
	return 429
}

func (o *DeletePolicyTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeletePolicyTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /policies/{pid}][%d] deletePolicyTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeletePolicyTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePolicyTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
