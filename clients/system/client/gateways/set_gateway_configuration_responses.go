// Code generated by go-swagger; DO NOT EDIT.

package gateways

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// SetGatewayConfigurationReader is a Reader for the SetGatewayConfiguration structure.
type SetGatewayConfigurationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetGatewayConfigurationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetGatewayConfigurationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSetGatewayConfigurationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetGatewayConfigurationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetGatewayConfigurationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSetGatewayConfigurationConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetGatewayConfigurationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetGatewayConfigurationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSetGatewayConfigurationOK creates a SetGatewayConfigurationOK with default headers values
func NewSetGatewayConfigurationOK() *SetGatewayConfigurationOK {
	return &SetGatewayConfigurationOK{}
}

/*
SetGatewayConfigurationOK describes a response with status code 200, with default header values.

Set gateway configuration response
*/
type SetGatewayConfigurationOK struct {
	Payload *models.SetGatewayConfigurationResponse
}

// IsSuccess returns true when this set gateway configuration o k response has a 2xx status code
func (o *SetGatewayConfigurationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set gateway configuration o k response has a 3xx status code
func (o *SetGatewayConfigurationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration o k response has a 4xx status code
func (o *SetGatewayConfigurationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this set gateway configuration o k response has a 5xx status code
func (o *SetGatewayConfigurationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration o k response a status code equal to that given
func (o *SetGatewayConfigurationOK) IsCode(code int) bool {
	return code == 200
}

func (o *SetGatewayConfigurationOK) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationOK  %+v", 200, o.Payload)
}

func (o *SetGatewayConfigurationOK) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationOK  %+v", 200, o.Payload)
}

func (o *SetGatewayConfigurationOK) GetPayload() *models.SetGatewayConfigurationResponse {
	return o.Payload
}

func (o *SetGatewayConfigurationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SetGatewayConfigurationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationUnauthorized creates a SetGatewayConfigurationUnauthorized with default headers values
func NewSetGatewayConfigurationUnauthorized() *SetGatewayConfigurationUnauthorized {
	return &SetGatewayConfigurationUnauthorized{}
}

/*
SetGatewayConfigurationUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type SetGatewayConfigurationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration unauthorized response has a 2xx status code
func (o *SetGatewayConfigurationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration unauthorized response has a 3xx status code
func (o *SetGatewayConfigurationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration unauthorized response has a 4xx status code
func (o *SetGatewayConfigurationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration unauthorized response has a 5xx status code
func (o *SetGatewayConfigurationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration unauthorized response a status code equal to that given
func (o *SetGatewayConfigurationUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SetGatewayConfigurationUnauthorized) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *SetGatewayConfigurationUnauthorized) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationUnauthorized  %+v", 401, o.Payload)
}

func (o *SetGatewayConfigurationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationForbidden creates a SetGatewayConfigurationForbidden with default headers values
func NewSetGatewayConfigurationForbidden() *SetGatewayConfigurationForbidden {
	return &SetGatewayConfigurationForbidden{}
}

/*
SetGatewayConfigurationForbidden describes a response with status code 403, with default header values.

HttpError
*/
type SetGatewayConfigurationForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration forbidden response has a 2xx status code
func (o *SetGatewayConfigurationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration forbidden response has a 3xx status code
func (o *SetGatewayConfigurationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration forbidden response has a 4xx status code
func (o *SetGatewayConfigurationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration forbidden response has a 5xx status code
func (o *SetGatewayConfigurationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration forbidden response a status code equal to that given
func (o *SetGatewayConfigurationForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SetGatewayConfigurationForbidden) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *SetGatewayConfigurationForbidden) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationForbidden  %+v", 403, o.Payload)
}

func (o *SetGatewayConfigurationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationNotFound creates a SetGatewayConfigurationNotFound with default headers values
func NewSetGatewayConfigurationNotFound() *SetGatewayConfigurationNotFound {
	return &SetGatewayConfigurationNotFound{}
}

/*
SetGatewayConfigurationNotFound describes a response with status code 404, with default header values.

HttpError
*/
type SetGatewayConfigurationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration not found response has a 2xx status code
func (o *SetGatewayConfigurationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration not found response has a 3xx status code
func (o *SetGatewayConfigurationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration not found response has a 4xx status code
func (o *SetGatewayConfigurationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration not found response has a 5xx status code
func (o *SetGatewayConfigurationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration not found response a status code equal to that given
func (o *SetGatewayConfigurationNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SetGatewayConfigurationNotFound) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *SetGatewayConfigurationNotFound) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationNotFound  %+v", 404, o.Payload)
}

func (o *SetGatewayConfigurationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationConflict creates a SetGatewayConfigurationConflict with default headers values
func NewSetGatewayConfigurationConflict() *SetGatewayConfigurationConflict {
	return &SetGatewayConfigurationConflict{}
}

/*
SetGatewayConfigurationConflict describes a response with status code 409, with default header values.

HttpError
*/
type SetGatewayConfigurationConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration conflict response has a 2xx status code
func (o *SetGatewayConfigurationConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration conflict response has a 3xx status code
func (o *SetGatewayConfigurationConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration conflict response has a 4xx status code
func (o *SetGatewayConfigurationConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration conflict response has a 5xx status code
func (o *SetGatewayConfigurationConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration conflict response a status code equal to that given
func (o *SetGatewayConfigurationConflict) IsCode(code int) bool {
	return code == 409
}

func (o *SetGatewayConfigurationConflict) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationConflict  %+v", 409, o.Payload)
}

func (o *SetGatewayConfigurationConflict) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationConflict  %+v", 409, o.Payload)
}

func (o *SetGatewayConfigurationConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationUnprocessableEntity creates a SetGatewayConfigurationUnprocessableEntity with default headers values
func NewSetGatewayConfigurationUnprocessableEntity() *SetGatewayConfigurationUnprocessableEntity {
	return &SetGatewayConfigurationUnprocessableEntity{}
}

/*
SetGatewayConfigurationUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type SetGatewayConfigurationUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration unprocessable entity response has a 2xx status code
func (o *SetGatewayConfigurationUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration unprocessable entity response has a 3xx status code
func (o *SetGatewayConfigurationUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration unprocessable entity response has a 4xx status code
func (o *SetGatewayConfigurationUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration unprocessable entity response has a 5xx status code
func (o *SetGatewayConfigurationUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration unprocessable entity response a status code equal to that given
func (o *SetGatewayConfigurationUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *SetGatewayConfigurationUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetGatewayConfigurationUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetGatewayConfigurationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetGatewayConfigurationTooManyRequests creates a SetGatewayConfigurationTooManyRequests with default headers values
func NewSetGatewayConfigurationTooManyRequests() *SetGatewayConfigurationTooManyRequests {
	return &SetGatewayConfigurationTooManyRequests{}
}

/*
SetGatewayConfigurationTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type SetGatewayConfigurationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set gateway configuration too many requests response has a 2xx status code
func (o *SetGatewayConfigurationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set gateway configuration too many requests response has a 3xx status code
func (o *SetGatewayConfigurationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set gateway configuration too many requests response has a 4xx status code
func (o *SetGatewayConfigurationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set gateway configuration too many requests response has a 5xx status code
func (o *SetGatewayConfigurationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set gateway configuration too many requests response a status code equal to that given
func (o *SetGatewayConfigurationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SetGatewayConfigurationTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetGatewayConfigurationTooManyRequests) String() string {
	return fmt.Sprintf("[POST /gateways/configuration][%d] setGatewayConfigurationTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetGatewayConfigurationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetGatewayConfigurationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
