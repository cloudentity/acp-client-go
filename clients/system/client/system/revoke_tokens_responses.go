// Code generated by go-swagger; DO NOT EDIT.

package system

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// RevokeTokensReader is a Reader for the RevokeTokens structure.
type RevokeTokensReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeTokensReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRevokeTokensNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeTokensUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeTokensForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeTokensNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRevokeTokensUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /servers/{wid}/tokens] revokeTokens", response, response.Code())
	}
}

// NewRevokeTokensNoContent creates a RevokeTokensNoContent with default headers values
func NewRevokeTokensNoContent() *RevokeTokensNoContent {
	return &RevokeTokensNoContent{}
}

/*
RevokeTokensNoContent describes a response with status code 204, with default header values.

	Tokens removed
*/
type RevokeTokensNoContent struct {
}

// IsSuccess returns true when this revoke tokens no content response has a 2xx status code
func (o *RevokeTokensNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke tokens no content response has a 3xx status code
func (o *RevokeTokensNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke tokens no content response has a 4xx status code
func (o *RevokeTokensNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke tokens no content response has a 5xx status code
func (o *RevokeTokensNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke tokens no content response a status code equal to that given
func (o *RevokeTokensNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the revoke tokens no content response
func (o *RevokeTokensNoContent) Code() int {
	return 204
}

func (o *RevokeTokensNoContent) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensNoContent ", 204)
}

func (o *RevokeTokensNoContent) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensNoContent ", 204)
}

func (o *RevokeTokensNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeTokensUnauthorized creates a RevokeTokensUnauthorized with default headers values
func NewRevokeTokensUnauthorized() *RevokeTokensUnauthorized {
	return &RevokeTokensUnauthorized{}
}

/*
RevokeTokensUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeTokensUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke tokens unauthorized response has a 2xx status code
func (o *RevokeTokensUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke tokens unauthorized response has a 3xx status code
func (o *RevokeTokensUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke tokens unauthorized response has a 4xx status code
func (o *RevokeTokensUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke tokens unauthorized response has a 5xx status code
func (o *RevokeTokensUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke tokens unauthorized response a status code equal to that given
func (o *RevokeTokensUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke tokens unauthorized response
func (o *RevokeTokensUnauthorized) Code() int {
	return 401
}

func (o *RevokeTokensUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeTokensUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensUnauthorized  %+v", 401, o.Payload)
}

func (o *RevokeTokensUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeTokensUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeTokensForbidden creates a RevokeTokensForbidden with default headers values
func NewRevokeTokensForbidden() *RevokeTokensForbidden {
	return &RevokeTokensForbidden{}
}

/*
RevokeTokensForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeTokensForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke tokens forbidden response has a 2xx status code
func (o *RevokeTokensForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke tokens forbidden response has a 3xx status code
func (o *RevokeTokensForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke tokens forbidden response has a 4xx status code
func (o *RevokeTokensForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke tokens forbidden response has a 5xx status code
func (o *RevokeTokensForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke tokens forbidden response a status code equal to that given
func (o *RevokeTokensForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke tokens forbidden response
func (o *RevokeTokensForbidden) Code() int {
	return 403
}

func (o *RevokeTokensForbidden) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensForbidden  %+v", 403, o.Payload)
}

func (o *RevokeTokensForbidden) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensForbidden  %+v", 403, o.Payload)
}

func (o *RevokeTokensForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeTokensForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeTokensNotFound creates a RevokeTokensNotFound with default headers values
func NewRevokeTokensNotFound() *RevokeTokensNotFound {
	return &RevokeTokensNotFound{}
}

/*
RevokeTokensNotFound describes a response with status code 404, with default header values.

Not found
*/
type RevokeTokensNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke tokens not found response has a 2xx status code
func (o *RevokeTokensNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke tokens not found response has a 3xx status code
func (o *RevokeTokensNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke tokens not found response has a 4xx status code
func (o *RevokeTokensNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke tokens not found response has a 5xx status code
func (o *RevokeTokensNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke tokens not found response a status code equal to that given
func (o *RevokeTokensNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke tokens not found response
func (o *RevokeTokensNotFound) Code() int {
	return 404
}

func (o *RevokeTokensNotFound) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensNotFound  %+v", 404, o.Payload)
}

func (o *RevokeTokensNotFound) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensNotFound  %+v", 404, o.Payload)
}

func (o *RevokeTokensNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeTokensNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeTokensUnprocessableEntity creates a RevokeTokensUnprocessableEntity with default headers values
func NewRevokeTokensUnprocessableEntity() *RevokeTokensUnprocessableEntity {
	return &RevokeTokensUnprocessableEntity{}
}

/*
RevokeTokensUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type RevokeTokensUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke tokens unprocessable entity response has a 2xx status code
func (o *RevokeTokensUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke tokens unprocessable entity response has a 3xx status code
func (o *RevokeTokensUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke tokens unprocessable entity response has a 4xx status code
func (o *RevokeTokensUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke tokens unprocessable entity response has a 5xx status code
func (o *RevokeTokensUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke tokens unprocessable entity response a status code equal to that given
func (o *RevokeTokensUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the revoke tokens unprocessable entity response
func (o *RevokeTokensUnprocessableEntity) Code() int {
	return 422
}

func (o *RevokeTokensUnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *RevokeTokensUnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/tokens][%d] revokeTokensUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *RevokeTokensUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeTokensUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
