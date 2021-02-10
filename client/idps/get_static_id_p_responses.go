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

// GetStaticIDPReader is a Reader for the GetStaticIDP structure.
type GetStaticIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetStaticIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetStaticIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetStaticIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetStaticIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetStaticIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetStaticIDPOK creates a GetStaticIDPOK with default headers values
func NewGetStaticIDPOK() *GetStaticIDPOK {
	return &GetStaticIDPOK{}
}

/* GetStaticIDPOK describes a response with status code 200, with default header values.

StaticIDP
*/
type GetStaticIDPOK struct {
	Payload *models.StaticIDP
}

func (o *GetStaticIDPOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/static/{iid}][%d] getStaticIdPOK  %+v", 200, o.Payload)
}
func (o *GetStaticIDPOK) GetPayload() *models.StaticIDP {
	return o.Payload
}

func (o *GetStaticIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.StaticIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPUnauthorized creates a GetStaticIDPUnauthorized with default headers values
func NewGetStaticIDPUnauthorized() *GetStaticIDPUnauthorized {
	return &GetStaticIDPUnauthorized{}
}

/* GetStaticIDPUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetStaticIDPUnauthorized struct {
	Payload *models.Error
}

func (o *GetStaticIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/static/{iid}][%d] getStaticIdPUnauthorized  %+v", 401, o.Payload)
}
func (o *GetStaticIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPForbidden creates a GetStaticIDPForbidden with default headers values
func NewGetStaticIDPForbidden() *GetStaticIDPForbidden {
	return &GetStaticIDPForbidden{}
}

/* GetStaticIDPForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetStaticIDPForbidden struct {
	Payload *models.Error
}

func (o *GetStaticIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/static/{iid}][%d] getStaticIdPForbidden  %+v", 403, o.Payload)
}
func (o *GetStaticIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPNotFound creates a GetStaticIDPNotFound with default headers values
func NewGetStaticIDPNotFound() *GetStaticIDPNotFound {
	return &GetStaticIDPNotFound{}
}

/* GetStaticIDPNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetStaticIDPNotFound struct {
	Payload *models.Error
}

func (o *GetStaticIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/idps/static/{iid}][%d] getStaticIdPNotFound  %+v", 404, o.Payload)
}
func (o *GetStaticIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
