// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetMFAMethodReader is a Reader for the GetMFAMethod structure.
type GetMFAMethodReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMFAMethodReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMFAMethodOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetMFAMethodUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMFAMethodForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMFAMethodNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetMFAMethodTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetMFAMethodOK creates a GetMFAMethodOK with default headers values
func NewGetMFAMethodOK() *GetMFAMethodOK {
	return &GetMFAMethodOK{}
}

/* GetMFAMethodOK describes a response with status code 200, with default header values.

MFA method
*/
type GetMFAMethodOK struct {
	Payload *models.MFAMethodResponse
}

func (o *GetMFAMethodOK) Error() string {
	return fmt.Sprintf("[GET /mfa-methods/{mfaID}][%d] getMFAMethodOK  %+v", 200, o.Payload)
}
func (o *GetMFAMethodOK) GetPayload() *models.MFAMethodResponse {
	return o.Payload
}

func (o *GetMFAMethodOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MFAMethodResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMFAMethodUnauthorized creates a GetMFAMethodUnauthorized with default headers values
func NewGetMFAMethodUnauthorized() *GetMFAMethodUnauthorized {
	return &GetMFAMethodUnauthorized{}
}

/* GetMFAMethodUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetMFAMethodUnauthorized struct {
	Payload *models.Error
}

func (o *GetMFAMethodUnauthorized) Error() string {
	return fmt.Sprintf("[GET /mfa-methods/{mfaID}][%d] getMFAMethodUnauthorized  %+v", 401, o.Payload)
}
func (o *GetMFAMethodUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMFAMethodUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMFAMethodForbidden creates a GetMFAMethodForbidden with default headers values
func NewGetMFAMethodForbidden() *GetMFAMethodForbidden {
	return &GetMFAMethodForbidden{}
}

/* GetMFAMethodForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetMFAMethodForbidden struct {
	Payload *models.Error
}

func (o *GetMFAMethodForbidden) Error() string {
	return fmt.Sprintf("[GET /mfa-methods/{mfaID}][%d] getMFAMethodForbidden  %+v", 403, o.Payload)
}
func (o *GetMFAMethodForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMFAMethodForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMFAMethodNotFound creates a GetMFAMethodNotFound with default headers values
func NewGetMFAMethodNotFound() *GetMFAMethodNotFound {
	return &GetMFAMethodNotFound{}
}

/* GetMFAMethodNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetMFAMethodNotFound struct {
	Payload *models.Error
}

func (o *GetMFAMethodNotFound) Error() string {
	return fmt.Sprintf("[GET /mfa-methods/{mfaID}][%d] getMFAMethodNotFound  %+v", 404, o.Payload)
}
func (o *GetMFAMethodNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMFAMethodNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMFAMethodTooManyRequests creates a GetMFAMethodTooManyRequests with default headers values
func NewGetMFAMethodTooManyRequests() *GetMFAMethodTooManyRequests {
	return &GetMFAMethodTooManyRequests{}
}

/* GetMFAMethodTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetMFAMethodTooManyRequests struct {
	Payload *models.Error
}

func (o *GetMFAMethodTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /mfa-methods/{mfaID}][%d] getMFAMethodTooManyRequests  %+v", 429, o.Payload)
}
func (o *GetMFAMethodTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMFAMethodTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}