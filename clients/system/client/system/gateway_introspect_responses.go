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

// GatewayIntrospectReader is a Reader for the GatewayIntrospect structure.
type GatewayIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GatewayIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGatewayIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGatewayIntrospectBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGatewayIntrospectUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGatewayIntrospectOK creates a GatewayIntrospectOK with default headers values
func NewGatewayIntrospectOK() *GatewayIntrospectOK {
	return &GatewayIntrospectOK{}
}

/*
GatewayIntrospectOK describes a response with status code 200, with default header values.

Introspect
*/
type GatewayIntrospectOK struct {
	Payload *models.IntrospectResponse
}

// IsSuccess returns true when this gateway introspect o k response has a 2xx status code
func (o *GatewayIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gateway introspect o k response has a 3xx status code
func (o *GatewayIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gateway introspect o k response has a 4xx status code
func (o *GatewayIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gateway introspect o k response has a 5xx status code
func (o *GatewayIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gateway introspect o k response a status code equal to that given
func (o *GatewayIntrospectOK) IsCode(code int) bool {
	return code == 200
}

func (o *GatewayIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectOK  %+v", 200, o.Payload)
}

func (o *GatewayIntrospectOK) String() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectOK  %+v", 200, o.Payload)
}

func (o *GatewayIntrospectOK) GetPayload() *models.IntrospectResponse {
	return o.Payload
}

func (o *GatewayIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IntrospectResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGatewayIntrospectBadRequest creates a GatewayIntrospectBadRequest with default headers values
func NewGatewayIntrospectBadRequest() *GatewayIntrospectBadRequest {
	return &GatewayIntrospectBadRequest{}
}

/*
GatewayIntrospectBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type GatewayIntrospectBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this gateway introspect bad request response has a 2xx status code
func (o *GatewayIntrospectBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this gateway introspect bad request response has a 3xx status code
func (o *GatewayIntrospectBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gateway introspect bad request response has a 4xx status code
func (o *GatewayIntrospectBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this gateway introspect bad request response has a 5xx status code
func (o *GatewayIntrospectBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this gateway introspect bad request response a status code equal to that given
func (o *GatewayIntrospectBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *GatewayIntrospectBadRequest) Error() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectBadRequest  %+v", 400, o.Payload)
}

func (o *GatewayIntrospectBadRequest) String() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectBadRequest  %+v", 400, o.Payload)
}

func (o *GatewayIntrospectBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GatewayIntrospectBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGatewayIntrospectUnprocessableEntity creates a GatewayIntrospectUnprocessableEntity with default headers values
func NewGatewayIntrospectUnprocessableEntity() *GatewayIntrospectUnprocessableEntity {
	return &GatewayIntrospectUnprocessableEntity{}
}

/*
GatewayIntrospectUnprocessableEntity describes a response with status code 422, with default header values.

HttpError
*/
type GatewayIntrospectUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this gateway introspect unprocessable entity response has a 2xx status code
func (o *GatewayIntrospectUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this gateway introspect unprocessable entity response has a 3xx status code
func (o *GatewayIntrospectUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gateway introspect unprocessable entity response has a 4xx status code
func (o *GatewayIntrospectUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this gateway introspect unprocessable entity response has a 5xx status code
func (o *GatewayIntrospectUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this gateway introspect unprocessable entity response a status code equal to that given
func (o *GatewayIntrospectUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

func (o *GatewayIntrospectUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GatewayIntrospectUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /gateways/introspect][%d] gatewayIntrospectUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GatewayIntrospectUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GatewayIntrospectUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
