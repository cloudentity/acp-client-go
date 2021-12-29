// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetOktaIDPReader is a Reader for the GetOktaIDP structure.
type GetOktaIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOktaIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOktaIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetOktaIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOktaIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOktaIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOktaIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetOktaIDPOK creates a GetOktaIDPOK with default headers values
func NewGetOktaIDPOK() *GetOktaIDPOK {
	return &GetOktaIDPOK{}
}

/* GetOktaIDPOK describes a response with status code 200, with default header values.

OktaIDP
*/
type GetOktaIDPOK struct {
	Payload *models.OktaIDP
}

func (o *GetOktaIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/okta/{iid}][%d] getOktaIdPOK  %+v", 200, o.Payload)
}
func (o *GetOktaIDPOK) GetPayload() *models.OktaIDP {
	return o.Payload
}

func (o *GetOktaIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OktaIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOktaIDPUnauthorized creates a GetOktaIDPUnauthorized with default headers values
func NewGetOktaIDPUnauthorized() *GetOktaIDPUnauthorized {
	return &GetOktaIDPUnauthorized{}
}

/* GetOktaIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetOktaIDPUnauthorized struct {
	Payload *models.Error
}

func (o *GetOktaIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/okta/{iid}][%d] getOktaIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *GetOktaIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOktaIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOktaIDPForbidden creates a GetOktaIDPForbidden with default headers values
func NewGetOktaIDPForbidden() *GetOktaIDPForbidden {
	return &GetOktaIDPForbidden{}
}

/* GetOktaIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetOktaIDPForbidden struct {
	Payload *models.Error
}

func (o *GetOktaIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/okta/{iid}][%d] getOktaIdPForbidden  %+v", 403, o.Payload)
}
func (o *GetOktaIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOktaIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOktaIDPNotFound creates a GetOktaIDPNotFound with default headers values
func NewGetOktaIDPNotFound() *GetOktaIDPNotFound {
	return &GetOktaIDPNotFound{}
}

/* GetOktaIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetOktaIDPNotFound struct {
	Payload *models.Error
}

func (o *GetOktaIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/okta/{iid}][%d] getOktaIdPNotFound  %+v", 404, o.Payload)
}
func (o *GetOktaIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOktaIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOktaIDPTooManyRequests creates a GetOktaIDPTooManyRequests with default headers values
func NewGetOktaIDPTooManyRequests() *GetOktaIDPTooManyRequests {
	return &GetOktaIDPTooManyRequests{}
}

/* GetOktaIDPTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetOktaIDPTooManyRequests struct {
	Payload *models.Error
}

func (o *GetOktaIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/okta/{iid}][%d] getOktaIdPTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetOktaIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOktaIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
