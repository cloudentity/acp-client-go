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

// BindGroupToServiceReader is a Reader for the BindGroupToService structure.
type BindGroupToServiceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BindGroupToServiceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBindGroupToServiceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewBindGroupToServiceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewBindGroupToServiceUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewBindGroupToServiceForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewBindGroupToServiceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewBindGroupToServiceUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewBindGroupToServiceTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewBindGroupToServiceOK creates a BindGroupToServiceOK with default headers values
func NewBindGroupToServiceOK() *BindGroupToServiceOK {
	return &BindGroupToServiceOK{}
}

/*
BindGroupToServiceOK describes a response with status code 200, with default header values.

Bind group to service response
*/
type BindGroupToServiceOK struct {
	Payload *models.RemoveServiceConfigurationResult
}

// IsSuccess returns true when this bind group to service o k response has a 2xx status code
func (o *BindGroupToServiceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bind group to service o k response has a 3xx status code
func (o *BindGroupToServiceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service o k response has a 4xx status code
func (o *BindGroupToServiceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this bind group to service o k response has a 5xx status code
func (o *BindGroupToServiceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service o k response a status code equal to that given
func (o *BindGroupToServiceOK) IsCode(code int) bool {
	return code == 200
}

func (o *BindGroupToServiceOK) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceOK  %+v", 200, o.Payload)
}

func (o *BindGroupToServiceOK) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceOK  %+v", 200, o.Payload)
}

func (o *BindGroupToServiceOK) GetPayload() *models.RemoveServiceConfigurationResult {
	return o.Payload
}

func (o *BindGroupToServiceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RemoveServiceConfigurationResult)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceBadRequest creates a BindGroupToServiceBadRequest with default headers values
func NewBindGroupToServiceBadRequest() *BindGroupToServiceBadRequest {
	return &BindGroupToServiceBadRequest{}
}

/*
BindGroupToServiceBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type BindGroupToServiceBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service bad request response has a 2xx status code
func (o *BindGroupToServiceBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service bad request response has a 3xx status code
func (o *BindGroupToServiceBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service bad request response has a 4xx status code
func (o *BindGroupToServiceBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service bad request response has a 5xx status code
func (o *BindGroupToServiceBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service bad request response a status code equal to that given
func (o *BindGroupToServiceBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *BindGroupToServiceBadRequest) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceBadRequest  %+v", 400, o.Payload)
}

func (o *BindGroupToServiceBadRequest) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceBadRequest  %+v", 400, o.Payload)
}

func (o *BindGroupToServiceBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceUnauthorized creates a BindGroupToServiceUnauthorized with default headers values
func NewBindGroupToServiceUnauthorized() *BindGroupToServiceUnauthorized {
	return &BindGroupToServiceUnauthorized{}
}

/*
BindGroupToServiceUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type BindGroupToServiceUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service unauthorized response has a 2xx status code
func (o *BindGroupToServiceUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service unauthorized response has a 3xx status code
func (o *BindGroupToServiceUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service unauthorized response has a 4xx status code
func (o *BindGroupToServiceUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service unauthorized response has a 5xx status code
func (o *BindGroupToServiceUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service unauthorized response a status code equal to that given
func (o *BindGroupToServiceUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *BindGroupToServiceUnauthorized) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceUnauthorized  %+v", 401, o.Payload)
}

func (o *BindGroupToServiceUnauthorized) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceUnauthorized  %+v", 401, o.Payload)
}

func (o *BindGroupToServiceUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceForbidden creates a BindGroupToServiceForbidden with default headers values
func NewBindGroupToServiceForbidden() *BindGroupToServiceForbidden {
	return &BindGroupToServiceForbidden{}
}

/*
BindGroupToServiceForbidden describes a response with status code 403, with default header values.

HttpError
*/
type BindGroupToServiceForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service forbidden response has a 2xx status code
func (o *BindGroupToServiceForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service forbidden response has a 3xx status code
func (o *BindGroupToServiceForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service forbidden response has a 4xx status code
func (o *BindGroupToServiceForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service forbidden response has a 5xx status code
func (o *BindGroupToServiceForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service forbidden response a status code equal to that given
func (o *BindGroupToServiceForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *BindGroupToServiceForbidden) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceForbidden  %+v", 403, o.Payload)
}

func (o *BindGroupToServiceForbidden) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceForbidden  %+v", 403, o.Payload)
}

func (o *BindGroupToServiceForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceNotFound creates a BindGroupToServiceNotFound with default headers values
func NewBindGroupToServiceNotFound() *BindGroupToServiceNotFound {
	return &BindGroupToServiceNotFound{}
}

/*
BindGroupToServiceNotFound describes a response with status code 404, with default header values.

HttpError
*/
type BindGroupToServiceNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service not found response has a 2xx status code
func (o *BindGroupToServiceNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service not found response has a 3xx status code
func (o *BindGroupToServiceNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service not found response has a 4xx status code
func (o *BindGroupToServiceNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service not found response has a 5xx status code
func (o *BindGroupToServiceNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service not found response a status code equal to that given
func (o *BindGroupToServiceNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *BindGroupToServiceNotFound) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceNotFound  %+v", 404, o.Payload)
}

func (o *BindGroupToServiceNotFound) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceNotFound  %+v", 404, o.Payload)
}

func (o *BindGroupToServiceNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceUnprocessableEntity creates a BindGroupToServiceUnprocessableEntity with default headers values
func NewBindGroupToServiceUnprocessableEntity() *BindGroupToServiceUnprocessableEntity {
	return &BindGroupToServiceUnprocessableEntity{}
}

/*
BindGroupToServiceUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type BindGroupToServiceUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service unprocessable entity response has a 2xx status code
func (o *BindGroupToServiceUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service unprocessable entity response has a 3xx status code
func (o *BindGroupToServiceUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service unprocessable entity response has a 4xx status code
func (o *BindGroupToServiceUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service unprocessable entity response has a 5xx status code
func (o *BindGroupToServiceUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service unprocessable entity response a status code equal to that given
func (o *BindGroupToServiceUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *BindGroupToServiceUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *BindGroupToServiceUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *BindGroupToServiceUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBindGroupToServiceTooManyRequests creates a BindGroupToServiceTooManyRequests with default headers values
func NewBindGroupToServiceTooManyRequests() *BindGroupToServiceTooManyRequests {
	return &BindGroupToServiceTooManyRequests{}
}

/*
BindGroupToServiceTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type BindGroupToServiceTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this bind group to service too many requests response has a 2xx status code
func (o *BindGroupToServiceTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this bind group to service too many requests response has a 3xx status code
func (o *BindGroupToServiceTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bind group to service too many requests response has a 4xx status code
func (o *BindGroupToServiceTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this bind group to service too many requests response has a 5xx status code
func (o *BindGroupToServiceTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this bind group to service too many requests response a status code equal to that given
func (o *BindGroupToServiceTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *BindGroupToServiceTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceTooManyRequests  %+v", 429, o.Payload)
}

func (o *BindGroupToServiceTooManyRequests) String() string {
	return fmt.Sprintf("[POST /gateways/{gw}/groups/{apiGroup}/bind][%d] bindGroupToServiceTooManyRequests  %+v", 429, o.Payload)
}

func (o *BindGroupToServiceTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *BindGroupToServiceTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
