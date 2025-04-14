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

// GetMicrosoftIDPReader is a Reader for the GetMicrosoftIDP structure.
type GetMicrosoftIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetMicrosoftIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetMicrosoftIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetMicrosoftIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetMicrosoftIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetMicrosoftIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetMicrosoftIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/microsoft/{iid}] getMicrosoftIDP", response, response.Code())
	}
}

// NewGetMicrosoftIDPOK creates a GetMicrosoftIDPOK with default headers values
func NewGetMicrosoftIDPOK() *GetMicrosoftIDPOK {
	return &GetMicrosoftIDPOK{}
}

/*
GetMicrosoftIDPOK describes a response with status code 200, with default header values.

MicrosoftIDP
*/
type GetMicrosoftIDPOK struct {
	Payload *models.MicrosoftIDP
}

// IsSuccess returns true when this get microsoft Id p o k response has a 2xx status code
func (o *GetMicrosoftIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get microsoft Id p o k response has a 3xx status code
func (o *GetMicrosoftIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get microsoft Id p o k response has a 4xx status code
func (o *GetMicrosoftIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get microsoft Id p o k response has a 5xx status code
func (o *GetMicrosoftIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get microsoft Id p o k response a status code equal to that given
func (o *GetMicrosoftIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get microsoft Id p o k response
func (o *GetMicrosoftIDPOK) Code() int {
	return 200
}

func (o *GetMicrosoftIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPOK  %+v", 200, o.Payload)
}

func (o *GetMicrosoftIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPOK  %+v", 200, o.Payload)
}

func (o *GetMicrosoftIDPOK) GetPayload() *models.MicrosoftIDP {
	return o.Payload
}

func (o *GetMicrosoftIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MicrosoftIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMicrosoftIDPUnauthorized creates a GetMicrosoftIDPUnauthorized with default headers values
func NewGetMicrosoftIDPUnauthorized() *GetMicrosoftIDPUnauthorized {
	return &GetMicrosoftIDPUnauthorized{}
}

/*
GetMicrosoftIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetMicrosoftIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get microsoft Id p unauthorized response has a 2xx status code
func (o *GetMicrosoftIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get microsoft Id p unauthorized response has a 3xx status code
func (o *GetMicrosoftIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get microsoft Id p unauthorized response has a 4xx status code
func (o *GetMicrosoftIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get microsoft Id p unauthorized response has a 5xx status code
func (o *GetMicrosoftIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get microsoft Id p unauthorized response a status code equal to that given
func (o *GetMicrosoftIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get microsoft Id p unauthorized response
func (o *GetMicrosoftIDPUnauthorized) Code() int {
	return 401
}

func (o *GetMicrosoftIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMicrosoftIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetMicrosoftIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMicrosoftIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMicrosoftIDPForbidden creates a GetMicrosoftIDPForbidden with default headers values
func NewGetMicrosoftIDPForbidden() *GetMicrosoftIDPForbidden {
	return &GetMicrosoftIDPForbidden{}
}

/*
GetMicrosoftIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetMicrosoftIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get microsoft Id p forbidden response has a 2xx status code
func (o *GetMicrosoftIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get microsoft Id p forbidden response has a 3xx status code
func (o *GetMicrosoftIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get microsoft Id p forbidden response has a 4xx status code
func (o *GetMicrosoftIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get microsoft Id p forbidden response has a 5xx status code
func (o *GetMicrosoftIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get microsoft Id p forbidden response a status code equal to that given
func (o *GetMicrosoftIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get microsoft Id p forbidden response
func (o *GetMicrosoftIDPForbidden) Code() int {
	return 403
}

func (o *GetMicrosoftIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetMicrosoftIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetMicrosoftIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMicrosoftIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMicrosoftIDPNotFound creates a GetMicrosoftIDPNotFound with default headers values
func NewGetMicrosoftIDPNotFound() *GetMicrosoftIDPNotFound {
	return &GetMicrosoftIDPNotFound{}
}

/*
GetMicrosoftIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetMicrosoftIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get microsoft Id p not found response has a 2xx status code
func (o *GetMicrosoftIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get microsoft Id p not found response has a 3xx status code
func (o *GetMicrosoftIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get microsoft Id p not found response has a 4xx status code
func (o *GetMicrosoftIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get microsoft Id p not found response has a 5xx status code
func (o *GetMicrosoftIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get microsoft Id p not found response a status code equal to that given
func (o *GetMicrosoftIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get microsoft Id p not found response
func (o *GetMicrosoftIDPNotFound) Code() int {
	return 404
}

func (o *GetMicrosoftIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetMicrosoftIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetMicrosoftIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMicrosoftIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetMicrosoftIDPTooManyRequests creates a GetMicrosoftIDPTooManyRequests with default headers values
func NewGetMicrosoftIDPTooManyRequests() *GetMicrosoftIDPTooManyRequests {
	return &GetMicrosoftIDPTooManyRequests{}
}

/*
GetMicrosoftIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetMicrosoftIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get microsoft Id p too many requests response has a 2xx status code
func (o *GetMicrosoftIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get microsoft Id p too many requests response has a 3xx status code
func (o *GetMicrosoftIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get microsoft Id p too many requests response has a 4xx status code
func (o *GetMicrosoftIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get microsoft Id p too many requests response has a 5xx status code
func (o *GetMicrosoftIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get microsoft Id p too many requests response a status code equal to that given
func (o *GetMicrosoftIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get microsoft Id p too many requests response
func (o *GetMicrosoftIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetMicrosoftIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMicrosoftIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/microsoft/{iid}][%d] getMicrosoftIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetMicrosoftIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetMicrosoftIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
