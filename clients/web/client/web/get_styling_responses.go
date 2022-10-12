// Code generated by go-swagger; DO NOT EDIT.

package web

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/web/models"
)

// GetStylingReader is a Reader for the GetStyling structure.
type GetStylingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetStylingReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetStylingOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetStylingNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetStylingOK creates a GetStylingOK with default headers values
func NewGetStylingOK() *GetStylingOK {
	return &GetStylingOK{}
}

/*
GetStylingOK describes a response with status code 200, with default header values.

Styling
*/
type GetStylingOK struct {
	Payload *models.Styling
}

// IsSuccess returns true when this get styling o k response has a 2xx status code
func (o *GetStylingOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get styling o k response has a 3xx status code
func (o *GetStylingOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get styling o k response has a 4xx status code
func (o *GetStylingOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get styling o k response has a 5xx status code
func (o *GetStylingOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get styling o k response a status code equal to that given
func (o *GetStylingOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetStylingOK) Error() string {
	return fmt.Sprintf("[GET /styling][%d] getStylingOK  %+v", 200, o.Payload)
}

func (o *GetStylingOK) String() string {
	return fmt.Sprintf("[GET /styling][%d] getStylingOK  %+v", 200, o.Payload)
}

func (o *GetStylingOK) GetPayload() *models.Styling {
	return o.Payload
}

func (o *GetStylingOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Styling)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStylingNotFound creates a GetStylingNotFound with default headers values
func NewGetStylingNotFound() *GetStylingNotFound {
	return &GetStylingNotFound{}
}

/*
GetStylingNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetStylingNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get styling not found response has a 2xx status code
func (o *GetStylingNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get styling not found response has a 3xx status code
func (o *GetStylingNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get styling not found response has a 4xx status code
func (o *GetStylingNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get styling not found response has a 5xx status code
func (o *GetStylingNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get styling not found response a status code equal to that given
func (o *GetStylingNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetStylingNotFound) Error() string {
	return fmt.Sprintf("[GET /styling][%d] getStylingNotFound  %+v", 404, o.Payload)
}

func (o *GetStylingNotFound) String() string {
	return fmt.Sprintf("[GET /styling][%d] getStylingNotFound  %+v", 404, o.Payload)
}

func (o *GetStylingNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStylingNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
