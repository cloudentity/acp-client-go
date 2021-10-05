// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/models"
)

// ListScriptsReader is a Reader for the ListScripts structure.
type ListScriptsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListScriptsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListScriptsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListScriptsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListScriptsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListScriptsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListScriptsOK creates a ListScriptsOK with default headers values
func NewListScriptsOK() *ListScriptsOK {
	return &ListScriptsOK{}
}

/* ListScriptsOK describes a response with status code 200, with default header values.

Scripts
*/
type ListScriptsOK struct {
	Payload *models.Scripts
}

func (o *ListScriptsOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/scripts][%d] listScriptsOK  %+v", 200, o.Payload)
}
func (o *ListScriptsOK) GetPayload() *models.Scripts {
	return o.Payload
}

func (o *ListScriptsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Scripts)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptsBadRequest creates a ListScriptsBadRequest with default headers values
func NewListScriptsBadRequest() *ListScriptsBadRequest {
	return &ListScriptsBadRequest{}
}

/* ListScriptsBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ListScriptsBadRequest struct {
	Payload *models.Error
}

func (o *ListScriptsBadRequest) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/scripts][%d] listScriptsBadRequest  %+v", 400, o.Payload)
}
func (o *ListScriptsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptsUnauthorized creates a ListScriptsUnauthorized with default headers values
func NewListScriptsUnauthorized() *ListScriptsUnauthorized {
	return &ListScriptsUnauthorized{}
}

/* ListScriptsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListScriptsUnauthorized struct {
	Payload *models.Error
}

func (o *ListScriptsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/scripts][%d] listScriptsUnauthorized  %+v", 401, o.Payload)
}
func (o *ListScriptsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListScriptsForbidden creates a ListScriptsForbidden with default headers values
func NewListScriptsForbidden() *ListScriptsForbidden {
	return &ListScriptsForbidden{}
}

/* ListScriptsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListScriptsForbidden struct {
	Payload *models.Error
}

func (o *ListScriptsForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/{tid}/servers/{aid}/scripts][%d] listScriptsForbidden  %+v", 403, o.Payload)
}
func (o *ListScriptsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListScriptsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
