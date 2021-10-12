// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// ListMFAMethodsReader is a Reader for the ListMFAMethods structure.
type ListMFAMethodsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListMFAMethodsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListMFAMethodsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListMFAMethodsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListMFAMethodsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListMFAMethodsOK creates a ListMFAMethodsOK with default headers values
func NewListMFAMethodsOK() *ListMFAMethodsOK {
	return &ListMFAMethodsOK{}
}

/* ListMFAMethodsOK describes a response with status code 200, with default header values.

MFAMethods
*/
type ListMFAMethodsOK struct {
	Payload *models.MFAMethods
}

func (o *ListMFAMethodsOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/mfa-methods][%d] listMFAMethodsOK  %+v", 200, o.Payload)
}
func (o *ListMFAMethodsOK) GetPayload() *models.MFAMethods {
	return o.Payload
}

func (o *ListMFAMethodsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MFAMethods)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListMFAMethodsUnauthorized creates a ListMFAMethodsUnauthorized with default headers values
func NewListMFAMethodsUnauthorized() *ListMFAMethodsUnauthorized {
	return &ListMFAMethodsUnauthorized{}
}

/* ListMFAMethodsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListMFAMethodsUnauthorized struct {
	Payload *models.Error
}

func (o *ListMFAMethodsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/mfa-methods][%d] listMFAMethodsUnauthorized  %+v", 401, o.Payload)
}
func (o *ListMFAMethodsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListMFAMethodsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListMFAMethodsForbidden creates a ListMFAMethodsForbidden with default headers values
func NewListMFAMethodsForbidden() *ListMFAMethodsForbidden {
	return &ListMFAMethodsForbidden{}
}

/* ListMFAMethodsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListMFAMethodsForbidden struct {
	Payload *models.Error
}

func (o *ListMFAMethodsForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/mfa-methods][%d] listMFAMethodsForbidden  %+v", 403, o.Payload)
}
func (o *ListMFAMethodsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListMFAMethodsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}