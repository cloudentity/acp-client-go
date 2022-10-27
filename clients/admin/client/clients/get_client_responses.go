// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetClientReader is a Reader for the GetClient structure.
type GetClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetClientOK creates a GetClientOK with default headers values
func NewGetClientOK() *GetClientOK {
	return &GetClientOK{}
}

/*
GetClientOK describes a response with status code 200, with default header values.

Client
*/
type GetClientOK struct {
	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get client o k response has a 2xx status code
func (o *GetClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get client o k response has a 3xx status code
func (o *GetClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client o k response has a 4xx status code
func (o *GetClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get client o k response has a 5xx status code
func (o *GetClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get client o k response a status code equal to that given
func (o *GetClientOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetClientOK) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientOK  %+v", 200, o.Payload)
}

func (o *GetClientOK) String() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientOK  %+v", 200, o.Payload)
}

func (o *GetClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ClientAdminResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientUnauthorized creates a GetClientUnauthorized with default headers values
func NewGetClientUnauthorized() *GetClientUnauthorized {
	return &GetClientUnauthorized{}
}

/*
GetClientUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type GetClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client unauthorized response has a 2xx status code
func (o *GetClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client unauthorized response has a 3xx status code
func (o *GetClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client unauthorized response has a 4xx status code
func (o *GetClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client unauthorized response has a 5xx status code
func (o *GetClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get client unauthorized response a status code equal to that given
func (o *GetClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetClientUnauthorized) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetClientUnauthorized) String() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientForbidden creates a GetClientForbidden with default headers values
func NewGetClientForbidden() *GetClientForbidden {
	return &GetClientForbidden{}
}

/*
GetClientForbidden describes a response with status code 403, with default header values.

HttpError
*/
type GetClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client forbidden response has a 2xx status code
func (o *GetClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client forbidden response has a 3xx status code
func (o *GetClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client forbidden response has a 4xx status code
func (o *GetClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client forbidden response has a 5xx status code
func (o *GetClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get client forbidden response a status code equal to that given
func (o *GetClientForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetClientForbidden) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientForbidden  %+v", 403, o.Payload)
}

func (o *GetClientForbidden) String() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientForbidden  %+v", 403, o.Payload)
}

func (o *GetClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientNotFound creates a GetClientNotFound with default headers values
func NewGetClientNotFound() *GetClientNotFound {
	return &GetClientNotFound{}
}

/*
GetClientNotFound describes a response with status code 404, with default header values.

HttpError
*/
type GetClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client not found response has a 2xx status code
func (o *GetClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client not found response has a 3xx status code
func (o *GetClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client not found response has a 4xx status code
func (o *GetClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client not found response has a 5xx status code
func (o *GetClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get client not found response a status code equal to that given
func (o *GetClientNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *GetClientNotFound) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientNotFound  %+v", 404, o.Payload)
}

func (o *GetClientNotFound) String() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientNotFound  %+v", 404, o.Payload)
}

func (o *GetClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetClientTooManyRequests creates a GetClientTooManyRequests with default headers values
func NewGetClientTooManyRequests() *GetClientTooManyRequests {
	return &GetClientTooManyRequests{}
}

/*
GetClientTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type GetClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get client too many requests response has a 2xx status code
func (o *GetClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get client too many requests response has a 3xx status code
func (o *GetClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get client too many requests response has a 4xx status code
func (o *GetClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get client too many requests response has a 5xx status code
func (o *GetClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get client too many requests response a status code equal to that given
func (o *GetClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *GetClientTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetClientTooManyRequests) String() string {
	return fmt.Sprintf("[GET /clients/{cid}][%d] getClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
