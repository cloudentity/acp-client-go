// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// DeleteScriptReader is a Reader for the DeleteScript structure.
type DeleteScriptReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteScriptReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteScriptNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteScriptBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteScriptUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteScriptForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteScriptNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteScriptTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteScriptNoContent creates a DeleteScriptNoContent with default headers values
func NewDeleteScriptNoContent() *DeleteScriptNoContent {
	return &DeleteScriptNoContent{}
}

/*
DeleteScriptNoContent describes a response with status code 204, with default header values.

	Script has been deleted
*/
type DeleteScriptNoContent struct {
}

// IsSuccess returns true when this delete script no content response has a 2xx status code
func (o *DeleteScriptNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete script no content response has a 3xx status code
func (o *DeleteScriptNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script no content response has a 4xx status code
func (o *DeleteScriptNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete script no content response has a 5xx status code
func (o *DeleteScriptNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script no content response a status code equal to that given
func (o *DeleteScriptNoContent) IsCode(code int) bool {
	return code == 204
}

func (o *DeleteScriptNoContent) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptNoContent ", 204)
}

func (o *DeleteScriptNoContent) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptNoContent ", 204)
}

func (o *DeleteScriptNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteScriptBadRequest creates a DeleteScriptBadRequest with default headers values
func NewDeleteScriptBadRequest() *DeleteScriptBadRequest {
	return &DeleteScriptBadRequest{}
}

/*
DeleteScriptBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type DeleteScriptBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete script bad request response has a 2xx status code
func (o *DeleteScriptBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete script bad request response has a 3xx status code
func (o *DeleteScriptBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script bad request response has a 4xx status code
func (o *DeleteScriptBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete script bad request response has a 5xx status code
func (o *DeleteScriptBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script bad request response a status code equal to that given
func (o *DeleteScriptBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *DeleteScriptBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteScriptBadRequest) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteScriptBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteScriptBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteScriptUnauthorized creates a DeleteScriptUnauthorized with default headers values
func NewDeleteScriptUnauthorized() *DeleteScriptUnauthorized {
	return &DeleteScriptUnauthorized{}
}

/*
DeleteScriptUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type DeleteScriptUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete script unauthorized response has a 2xx status code
func (o *DeleteScriptUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete script unauthorized response has a 3xx status code
func (o *DeleteScriptUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script unauthorized response has a 4xx status code
func (o *DeleteScriptUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete script unauthorized response has a 5xx status code
func (o *DeleteScriptUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script unauthorized response a status code equal to that given
func (o *DeleteScriptUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *DeleteScriptUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteScriptUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteScriptUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteScriptUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteScriptForbidden creates a DeleteScriptForbidden with default headers values
func NewDeleteScriptForbidden() *DeleteScriptForbidden {
	return &DeleteScriptForbidden{}
}

/*
DeleteScriptForbidden describes a response with status code 403, with default header values.

HttpError
*/
type DeleteScriptForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete script forbidden response has a 2xx status code
func (o *DeleteScriptForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete script forbidden response has a 3xx status code
func (o *DeleteScriptForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script forbidden response has a 4xx status code
func (o *DeleteScriptForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete script forbidden response has a 5xx status code
func (o *DeleteScriptForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script forbidden response a status code equal to that given
func (o *DeleteScriptForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *DeleteScriptForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptForbidden  %+v", 403, o.Payload)
}

func (o *DeleteScriptForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptForbidden  %+v", 403, o.Payload)
}

func (o *DeleteScriptForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteScriptForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteScriptNotFound creates a DeleteScriptNotFound with default headers values
func NewDeleteScriptNotFound() *DeleteScriptNotFound {
	return &DeleteScriptNotFound{}
}

/*
DeleteScriptNotFound describes a response with status code 404, with default header values.

HttpError
*/
type DeleteScriptNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete script not found response has a 2xx status code
func (o *DeleteScriptNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete script not found response has a 3xx status code
func (o *DeleteScriptNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script not found response has a 4xx status code
func (o *DeleteScriptNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete script not found response has a 5xx status code
func (o *DeleteScriptNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script not found response a status code equal to that given
func (o *DeleteScriptNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *DeleteScriptNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptNotFound  %+v", 404, o.Payload)
}

func (o *DeleteScriptNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptNotFound  %+v", 404, o.Payload)
}

func (o *DeleteScriptNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteScriptNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteScriptTooManyRequests creates a DeleteScriptTooManyRequests with default headers values
func NewDeleteScriptTooManyRequests() *DeleteScriptTooManyRequests {
	return &DeleteScriptTooManyRequests{}
}

/*
DeleteScriptTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type DeleteScriptTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete script too many requests response has a 2xx status code
func (o *DeleteScriptTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete script too many requests response has a 3xx status code
func (o *DeleteScriptTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete script too many requests response has a 4xx status code
func (o *DeleteScriptTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete script too many requests response has a 5xx status code
func (o *DeleteScriptTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete script too many requests response a status code equal to that given
func (o *DeleteScriptTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *DeleteScriptTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteScriptTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/scripts/{script}][%d] deleteScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteScriptTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteScriptTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
