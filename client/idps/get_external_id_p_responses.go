// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// GetExternalIDPReader is a Reader for the GetExternalIDP structure.
type GetExternalIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetExternalIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetExternalIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetExternalIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetExternalIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetExternalIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetExternalIDPOK creates a GetExternalIDPOK with default headers values
func NewGetExternalIDPOK() *GetExternalIDPOK {
	return &GetExternalIDPOK{}
}

/* GetExternalIDPOK describes a response with status code 200, with default header values.

ExternalIDP
*/
type GetExternalIDPOK struct {
	Payload *models.ExternalIDP
}

func (o *GetExternalIDPOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/external/{iid}][%d] getExternalIdPOK  %+v", 200, o.Payload)
}
func (o *GetExternalIDPOK) GetPayload() *models.ExternalIDP {
	return o.Payload
}

func (o *GetExternalIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ExternalIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetExternalIDPUnauthorized creates a GetExternalIDPUnauthorized with default headers values
func NewGetExternalIDPUnauthorized() *GetExternalIDPUnauthorized {
	return &GetExternalIDPUnauthorized{}
}

/* GetExternalIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetExternalIDPUnauthorized struct {
	Payload *models.Error
}

func (o *GetExternalIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/external/{iid}][%d] getExternalIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *GetExternalIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetExternalIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetExternalIDPForbidden creates a GetExternalIDPForbidden with default headers values
func NewGetExternalIDPForbidden() *GetExternalIDPForbidden {
	return &GetExternalIDPForbidden{}
}

/* GetExternalIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetExternalIDPForbidden struct {
	Payload *models.Error
}

func (o *GetExternalIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/external/{iid}][%d] getExternalIdPForbidden  %+v", 403, o.Payload)
}
func (o *GetExternalIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetExternalIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetExternalIDPNotFound creates a GetExternalIDPNotFound with default headers values
func NewGetExternalIDPNotFound() *GetExternalIDPNotFound {
	return &GetExternalIDPNotFound{}
}

/* GetExternalIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetExternalIDPNotFound struct {
	Payload *models.Error
}

func (o *GetExternalIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/external/{iid}][%d] getExternalIdPNotFound  %+v", 404, o.Payload)
}
func (o *GetExternalIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetExternalIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
