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

// GetGatewayReader is a Reader for the GetGateway structure.
type GetGatewayReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGatewayReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGatewayOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetGatewayUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGatewayForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGatewayNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetGatewayOK creates a GetGatewayOK with default headers values
func NewGetGatewayOK() *GetGatewayOK {
	return &GetGatewayOK{}
}

/* GetGatewayOK describes a response with status code 200, with default header values.

GatewayWithClient
*/
type GetGatewayOK struct {
	Payload *models.GatewayWithClient
}

func (o *GetGatewayOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/gateways/{gw}][%d] getGatewayOK  %+v", 200, o.Payload)
}
func (o *GetGatewayOK) GetPayload() *models.GatewayWithClient {
	return o.Payload
}

func (o *GetGatewayOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GatewayWithClient)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGatewayUnauthorized creates a GetGatewayUnauthorized with default headers values
func NewGetGatewayUnauthorized() *GetGatewayUnauthorized {
	return &GetGatewayUnauthorized{}
}

/* GetGatewayUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetGatewayUnauthorized struct {
	Payload *models.Error
}

func (o *GetGatewayUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/gateways/{gw}][%d] getGatewayUnauthorized  %+v", 401, o.Payload)
}
func (o *GetGatewayUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGatewayUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGatewayForbidden creates a GetGatewayForbidden with default headers values
func NewGetGatewayForbidden() *GetGatewayForbidden {
	return &GetGatewayForbidden{}
}

/* GetGatewayForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetGatewayForbidden struct {
	Payload *models.Error
}

func (o *GetGatewayForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/gateways/{gw}][%d] getGatewayForbidden  %+v", 403, o.Payload)
}
func (o *GetGatewayForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGatewayForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGatewayNotFound creates a GetGatewayNotFound with default headers values
func NewGetGatewayNotFound() *GetGatewayNotFound {
	return &GetGatewayNotFound{}
}

/* GetGatewayNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetGatewayNotFound struct {
	Payload *models.Error
}

func (o *GetGatewayNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/gateways/{gw}][%d] getGatewayNotFound  %+v", 404, o.Payload)
}
func (o *GetGatewayNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGatewayNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
