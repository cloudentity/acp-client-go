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

// PushGatewayRequestsReader is a Reader for the PushGatewayRequests structure.
type PushGatewayRequestsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PushGatewayRequestsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPushGatewayRequestsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPushGatewayRequestsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPushGatewayRequestsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPushGatewayRequestsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPushGatewayRequestsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPushGatewayRequestsOK creates a PushGatewayRequestsOK with default headers values
func NewPushGatewayRequestsOK() *PushGatewayRequestsOK {
	return &PushGatewayRequestsOK{}
}

/*
PushGatewayRequestsOK describes a response with status code 200, with default header values.

Gateway requests events response
*/
type PushGatewayRequestsOK struct {
	Payload *models.GatewayRequestsEventsResponse
}

// IsSuccess returns true when this push gateway requests o k response has a 2xx status code
func (o *PushGatewayRequestsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this push gateway requests o k response has a 3xx status code
func (o *PushGatewayRequestsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this push gateway requests o k response has a 4xx status code
func (o *PushGatewayRequestsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this push gateway requests o k response has a 5xx status code
func (o *PushGatewayRequestsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this push gateway requests o k response a status code equal to that given
func (o *PushGatewayRequestsOK) IsCode(code int) bool {
	return code == 200
}

func (o *PushGatewayRequestsOK) Error() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsOK  %+v", 200, o.Payload)
}

func (o *PushGatewayRequestsOK) String() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsOK  %+v", 200, o.Payload)
}

func (o *PushGatewayRequestsOK) GetPayload() *models.GatewayRequestsEventsResponse {
	return o.Payload
}

func (o *PushGatewayRequestsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GatewayRequestsEventsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPushGatewayRequestsUnauthorized creates a PushGatewayRequestsUnauthorized with default headers values
func NewPushGatewayRequestsUnauthorized() *PushGatewayRequestsUnauthorized {
	return &PushGatewayRequestsUnauthorized{}
}

/*
PushGatewayRequestsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type PushGatewayRequestsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this push gateway requests unauthorized response has a 2xx status code
func (o *PushGatewayRequestsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this push gateway requests unauthorized response has a 3xx status code
func (o *PushGatewayRequestsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this push gateway requests unauthorized response has a 4xx status code
func (o *PushGatewayRequestsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this push gateway requests unauthorized response has a 5xx status code
func (o *PushGatewayRequestsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this push gateway requests unauthorized response a status code equal to that given
func (o *PushGatewayRequestsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *PushGatewayRequestsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsUnauthorized  %+v", 401, o.Payload)
}

func (o *PushGatewayRequestsUnauthorized) String() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsUnauthorized  %+v", 401, o.Payload)
}

func (o *PushGatewayRequestsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *PushGatewayRequestsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPushGatewayRequestsForbidden creates a PushGatewayRequestsForbidden with default headers values
func NewPushGatewayRequestsForbidden() *PushGatewayRequestsForbidden {
	return &PushGatewayRequestsForbidden{}
}

/*
PushGatewayRequestsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type PushGatewayRequestsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this push gateway requests forbidden response has a 2xx status code
func (o *PushGatewayRequestsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this push gateway requests forbidden response has a 3xx status code
func (o *PushGatewayRequestsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this push gateway requests forbidden response has a 4xx status code
func (o *PushGatewayRequestsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this push gateway requests forbidden response has a 5xx status code
func (o *PushGatewayRequestsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this push gateway requests forbidden response a status code equal to that given
func (o *PushGatewayRequestsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *PushGatewayRequestsForbidden) Error() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsForbidden  %+v", 403, o.Payload)
}

func (o *PushGatewayRequestsForbidden) String() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsForbidden  %+v", 403, o.Payload)
}

func (o *PushGatewayRequestsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *PushGatewayRequestsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPushGatewayRequestsNotFound creates a PushGatewayRequestsNotFound with default headers values
func NewPushGatewayRequestsNotFound() *PushGatewayRequestsNotFound {
	return &PushGatewayRequestsNotFound{}
}

/*
PushGatewayRequestsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type PushGatewayRequestsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this push gateway requests not found response has a 2xx status code
func (o *PushGatewayRequestsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this push gateway requests not found response has a 3xx status code
func (o *PushGatewayRequestsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this push gateway requests not found response has a 4xx status code
func (o *PushGatewayRequestsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this push gateway requests not found response has a 5xx status code
func (o *PushGatewayRequestsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this push gateway requests not found response a status code equal to that given
func (o *PushGatewayRequestsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *PushGatewayRequestsNotFound) Error() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsNotFound  %+v", 404, o.Payload)
}

func (o *PushGatewayRequestsNotFound) String() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsNotFound  %+v", 404, o.Payload)
}

func (o *PushGatewayRequestsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *PushGatewayRequestsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPushGatewayRequestsTooManyRequests creates a PushGatewayRequestsTooManyRequests with default headers values
func NewPushGatewayRequestsTooManyRequests() *PushGatewayRequestsTooManyRequests {
	return &PushGatewayRequestsTooManyRequests{}
}

/*
PushGatewayRequestsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type PushGatewayRequestsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this push gateway requests too many requests response has a 2xx status code
func (o *PushGatewayRequestsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this push gateway requests too many requests response has a 3xx status code
func (o *PushGatewayRequestsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this push gateway requests too many requests response has a 4xx status code
func (o *PushGatewayRequestsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this push gateway requests too many requests response has a 5xx status code
func (o *PushGatewayRequestsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this push gateway requests too many requests response a status code equal to that given
func (o *PushGatewayRequestsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *PushGatewayRequestsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsTooManyRequests  %+v", 429, o.Payload)
}

func (o *PushGatewayRequestsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /gateways/requests][%d] pushGatewayRequestsTooManyRequests  %+v", 429, o.Payload)
}

func (o *PushGatewayRequestsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *PushGatewayRequestsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
