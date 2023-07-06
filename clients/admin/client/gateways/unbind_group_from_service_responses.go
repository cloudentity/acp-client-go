// Code generated by go-swagger; DO NOT EDIT.

package gateways

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// UnbindGroupFromServiceReader is a Reader for the UnbindGroupFromService structure.
type UnbindGroupFromServiceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UnbindGroupFromServiceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUnbindGroupFromServiceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUnbindGroupFromServiceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUnbindGroupFromServiceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUnbindGroupFromServiceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUnbindGroupFromServiceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewUnbindGroupFromServiceUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUnbindGroupFromServiceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind] unbindGroupFromService", response, response.Code())
	}
}

// NewUnbindGroupFromServiceOK creates a UnbindGroupFromServiceOK with default headers values
func NewUnbindGroupFromServiceOK() *UnbindGroupFromServiceOK {
	return &UnbindGroupFromServiceOK{}
}

/*
UnbindGroupFromServiceOK describes a response with status code 200, with default header values.

Unbind group from service response
*/
type UnbindGroupFromServiceOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.RemoveServiceConfigurationResult
}

// IsSuccess returns true when this unbind group from service o k response has a 2xx status code
func (o *UnbindGroupFromServiceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this unbind group from service o k response has a 3xx status code
func (o *UnbindGroupFromServiceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service o k response has a 4xx status code
func (o *UnbindGroupFromServiceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this unbind group from service o k response has a 5xx status code
func (o *UnbindGroupFromServiceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service o k response a status code equal to that given
func (o *UnbindGroupFromServiceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the unbind group from service o k response
func (o *UnbindGroupFromServiceOK) Code() int {
	return 200
}

func (o *UnbindGroupFromServiceOK) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceOK  %+v", 200, o.Payload)
}

func (o *UnbindGroupFromServiceOK) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceOK  %+v", 200, o.Payload)
}

func (o *UnbindGroupFromServiceOK) GetPayload() *models.RemoveServiceConfigurationResult {
	return o.Payload
}

func (o *UnbindGroupFromServiceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.RemoveServiceConfigurationResult)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceBadRequest creates a UnbindGroupFromServiceBadRequest with default headers values
func NewUnbindGroupFromServiceBadRequest() *UnbindGroupFromServiceBadRequest {
	return &UnbindGroupFromServiceBadRequest{}
}

/*
UnbindGroupFromServiceBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type UnbindGroupFromServiceBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service bad request response has a 2xx status code
func (o *UnbindGroupFromServiceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service bad request response has a 3xx status code
func (o *UnbindGroupFromServiceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service bad request response has a 4xx status code
func (o *UnbindGroupFromServiceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service bad request response has a 5xx status code
func (o *UnbindGroupFromServiceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service bad request response a status code equal to that given
func (o *UnbindGroupFromServiceBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the unbind group from service bad request response
func (o *UnbindGroupFromServiceBadRequest) Code() int {
	return 400
}

func (o *UnbindGroupFromServiceBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceBadRequest  %+v", 400, o.Payload)
}

func (o *UnbindGroupFromServiceBadRequest) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceBadRequest  %+v", 400, o.Payload)
}

func (o *UnbindGroupFromServiceBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceUnauthorized creates a UnbindGroupFromServiceUnauthorized with default headers values
func NewUnbindGroupFromServiceUnauthorized() *UnbindGroupFromServiceUnauthorized {
	return &UnbindGroupFromServiceUnauthorized{}
}

/*
UnbindGroupFromServiceUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UnbindGroupFromServiceUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service unauthorized response has a 2xx status code
func (o *UnbindGroupFromServiceUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service unauthorized response has a 3xx status code
func (o *UnbindGroupFromServiceUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service unauthorized response has a 4xx status code
func (o *UnbindGroupFromServiceUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service unauthorized response has a 5xx status code
func (o *UnbindGroupFromServiceUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service unauthorized response a status code equal to that given
func (o *UnbindGroupFromServiceUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the unbind group from service unauthorized response
func (o *UnbindGroupFromServiceUnauthorized) Code() int {
	return 401
}

func (o *UnbindGroupFromServiceUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceUnauthorized  %+v", 401, o.Payload)
}

func (o *UnbindGroupFromServiceUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceUnauthorized  %+v", 401, o.Payload)
}

func (o *UnbindGroupFromServiceUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceForbidden creates a UnbindGroupFromServiceForbidden with default headers values
func NewUnbindGroupFromServiceForbidden() *UnbindGroupFromServiceForbidden {
	return &UnbindGroupFromServiceForbidden{}
}

/*
UnbindGroupFromServiceForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UnbindGroupFromServiceForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service forbidden response has a 2xx status code
func (o *UnbindGroupFromServiceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service forbidden response has a 3xx status code
func (o *UnbindGroupFromServiceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service forbidden response has a 4xx status code
func (o *UnbindGroupFromServiceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service forbidden response has a 5xx status code
func (o *UnbindGroupFromServiceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service forbidden response a status code equal to that given
func (o *UnbindGroupFromServiceForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the unbind group from service forbidden response
func (o *UnbindGroupFromServiceForbidden) Code() int {
	return 403
}

func (o *UnbindGroupFromServiceForbidden) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceForbidden  %+v", 403, o.Payload)
}

func (o *UnbindGroupFromServiceForbidden) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceForbidden  %+v", 403, o.Payload)
}

func (o *UnbindGroupFromServiceForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceNotFound creates a UnbindGroupFromServiceNotFound with default headers values
func NewUnbindGroupFromServiceNotFound() *UnbindGroupFromServiceNotFound {
	return &UnbindGroupFromServiceNotFound{}
}

/*
UnbindGroupFromServiceNotFound describes a response with status code 404, with default header values.

Not found
*/
type UnbindGroupFromServiceNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service not found response has a 2xx status code
func (o *UnbindGroupFromServiceNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service not found response has a 3xx status code
func (o *UnbindGroupFromServiceNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service not found response has a 4xx status code
func (o *UnbindGroupFromServiceNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service not found response has a 5xx status code
func (o *UnbindGroupFromServiceNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service not found response a status code equal to that given
func (o *UnbindGroupFromServiceNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the unbind group from service not found response
func (o *UnbindGroupFromServiceNotFound) Code() int {
	return 404
}

func (o *UnbindGroupFromServiceNotFound) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceNotFound  %+v", 404, o.Payload)
}

func (o *UnbindGroupFromServiceNotFound) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceNotFound  %+v", 404, o.Payload)
}

func (o *UnbindGroupFromServiceNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceUnprocessableEntity creates a UnbindGroupFromServiceUnprocessableEntity with default headers values
func NewUnbindGroupFromServiceUnprocessableEntity() *UnbindGroupFromServiceUnprocessableEntity {
	return &UnbindGroupFromServiceUnprocessableEntity{}
}

/*
UnbindGroupFromServiceUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type UnbindGroupFromServiceUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service unprocessable entity response has a 2xx status code
func (o *UnbindGroupFromServiceUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service unprocessable entity response has a 3xx status code
func (o *UnbindGroupFromServiceUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service unprocessable entity response has a 4xx status code
func (o *UnbindGroupFromServiceUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service unprocessable entity response has a 5xx status code
func (o *UnbindGroupFromServiceUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service unprocessable entity response a status code equal to that given
func (o *UnbindGroupFromServiceUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the unbind group from service unprocessable entity response
func (o *UnbindGroupFromServiceUnprocessableEntity) Code() int {
	return 422
}

func (o *UnbindGroupFromServiceUnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UnbindGroupFromServiceUnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *UnbindGroupFromServiceUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUnbindGroupFromServiceTooManyRequests creates a UnbindGroupFromServiceTooManyRequests with default headers values
func NewUnbindGroupFromServiceTooManyRequests() *UnbindGroupFromServiceTooManyRequests {
	return &UnbindGroupFromServiceTooManyRequests{}
}

/*
UnbindGroupFromServiceTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UnbindGroupFromServiceTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this unbind group from service too many requests response has a 2xx status code
func (o *UnbindGroupFromServiceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this unbind group from service too many requests response has a 3xx status code
func (o *UnbindGroupFromServiceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this unbind group from service too many requests response has a 4xx status code
func (o *UnbindGroupFromServiceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this unbind group from service too many requests response has a 5xx status code
func (o *UnbindGroupFromServiceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this unbind group from service too many requests response a status code equal to that given
func (o *UnbindGroupFromServiceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the unbind group from service too many requests response
func (o *UnbindGroupFromServiceTooManyRequests) Code() int {
	return 429
}

func (o *UnbindGroupFromServiceTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceTooManyRequests  %+v", 429, o.Payload)
}

func (o *UnbindGroupFromServiceTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /gateways/{gw}/groups/{apiGroup}/unbind][%d] unbindGroupFromServiceTooManyRequests  %+v", 429, o.Payload)
}

func (o *UnbindGroupFromServiceTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UnbindGroupFromServiceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
