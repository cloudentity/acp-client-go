// Code generated by go-swagger; DO NOT EDIT.

package gateways

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
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

/*PushGatewayRequestsOK handles this case with default header values.

GatewayRequestsEventsResponse
*/
type PushGatewayRequestsOK struct {
	Payload *models.GatewayRequestsEventsResponse
}

func (o *PushGatewayRequestsOK) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/gateways/requests][%d] pushGatewayRequestsOK  %+v", 200, o.Payload)
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

/*PushGatewayRequestsUnauthorized handles this case with default header values.

HttpError
*/
type PushGatewayRequestsUnauthorized struct {
	Payload *models.Error
}

func (o *PushGatewayRequestsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/gateways/requests][%d] pushGatewayRequestsUnauthorized  %+v", 401, o.Payload)
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

/*PushGatewayRequestsForbidden handles this case with default header values.

HttpError
*/
type PushGatewayRequestsForbidden struct {
	Payload *models.Error
}

func (o *PushGatewayRequestsForbidden) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/gateways/requests][%d] pushGatewayRequestsForbidden  %+v", 403, o.Payload)
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

/*PushGatewayRequestsNotFound handles this case with default header values.

HttpError
*/
type PushGatewayRequestsNotFound struct {
	Payload *models.Error
}

func (o *PushGatewayRequestsNotFound) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/gateways/requests][%d] pushGatewayRequestsNotFound  %+v", 404, o.Payload)
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

/*PushGatewayRequestsTooManyRequests handles this case with default header values.

HttpError
*/
type PushGatewayRequestsTooManyRequests struct {
	Payload *models.Error
}

func (o *PushGatewayRequestsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /api/system/{tid}/gateways/requests][%d] pushGatewayRequestsTooManyRequests  %+v", 429, o.Payload)
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
