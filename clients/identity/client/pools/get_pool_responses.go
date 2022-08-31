// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// GetPoolReader is a Reader for the GetPool structure.
type GetPoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPoolOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetPoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetPoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetPoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetPoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetPoolOK creates a GetPoolOK with default headers values
func NewGetPoolOK() *GetPoolOK {
	return &GetPoolOK{}
}

/* GetPoolOK describes a response with status code 200, with default header values.

Identity Pool
*/
type GetPoolOK struct {
	Payload *models.Pool
}

func (o *GetPoolOK) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}][%d] getPoolOK  %+v", 200, o.Payload)
}
func (o *GetPoolOK) GetPayload() *models.Pool {
	return o.Payload
}

func (o *GetPoolOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Pool)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPoolUnauthorized creates a GetPoolUnauthorized with default headers values
func NewGetPoolUnauthorized() *GetPoolUnauthorized {
	return &GetPoolUnauthorized{}
}

/* GetPoolUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetPoolUnauthorized struct {
	Payload *models.Error
}

func (o *GetPoolUnauthorized) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}][%d] getPoolUnauthorized  %+v", 401, o.Payload)
}
func (o *GetPoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPoolForbidden creates a GetPoolForbidden with default headers values
func NewGetPoolForbidden() *GetPoolForbidden {
	return &GetPoolForbidden{}
}

/* GetPoolForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetPoolForbidden struct {
	Payload *models.Error
}

func (o *GetPoolForbidden) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}][%d] getPoolForbidden  %+v", 403, o.Payload)
}
func (o *GetPoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPoolNotFound creates a GetPoolNotFound with default headers values
func NewGetPoolNotFound() *GetPoolNotFound {
	return &GetPoolNotFound{}
}

/* GetPoolNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetPoolNotFound struct {
	Payload *models.Error
}

func (o *GetPoolNotFound) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}][%d] getPoolNotFound  %+v", 404, o.Payload)
}
func (o *GetPoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPoolTooManyRequests creates a GetPoolTooManyRequests with default headers values
func NewGetPoolTooManyRequests() *GetPoolTooManyRequests {
	return &GetPoolTooManyRequests{}
}

/* GetPoolTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetPoolTooManyRequests struct {
	Payload *models.Error
}

func (o *GetPoolTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /admin/pools/{ipID}][%d] getPoolTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetPoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}