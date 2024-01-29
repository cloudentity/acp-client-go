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

// GetGoogleEmbeddedIDPReader is a Reader for the GetGoogleEmbeddedIDP structure.
type GetGoogleEmbeddedIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGoogleEmbeddedIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGoogleEmbeddedIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetGoogleEmbeddedIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGoogleEmbeddedIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGoogleEmbeddedIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetGoogleEmbeddedIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/google_embedded/{iid}] getGoogleEmbeddedIDP", response, response.Code())
	}
}

// NewGetGoogleEmbeddedIDPOK creates a GetGoogleEmbeddedIDPOK with default headers values
func NewGetGoogleEmbeddedIDPOK() *GetGoogleEmbeddedIDPOK {
	return &GetGoogleEmbeddedIDPOK{}
}

/*
GetGoogleEmbeddedIDPOK describes a response with status code 200, with default header values.

GoogleEmbeddedIDP
*/
type GetGoogleEmbeddedIDPOK struct {
	Payload *models.GoogleEmbeddedIDP
}

// IsSuccess returns true when this get google embedded Id p o k response has a 2xx status code
func (o *GetGoogleEmbeddedIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get google embedded Id p o k response has a 3xx status code
func (o *GetGoogleEmbeddedIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p o k response has a 4xx status code
func (o *GetGoogleEmbeddedIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get google embedded Id p o k response has a 5xx status code
func (o *GetGoogleEmbeddedIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p o k response a status code equal to that given
func (o *GetGoogleEmbeddedIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get google embedded Id p o k response
func (o *GetGoogleEmbeddedIDPOK) Code() int {
	return 200
}

func (o *GetGoogleEmbeddedIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPOK  %+v", 200, o.Payload)
}

func (o *GetGoogleEmbeddedIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPOK  %+v", 200, o.Payload)
}

func (o *GetGoogleEmbeddedIDPOK) GetPayload() *models.GoogleEmbeddedIDP {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GoogleEmbeddedIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPUnauthorized creates a GetGoogleEmbeddedIDPUnauthorized with default headers values
func NewGetGoogleEmbeddedIDPUnauthorized() *GetGoogleEmbeddedIDPUnauthorized {
	return &GetGoogleEmbeddedIDPUnauthorized{}
}

/*
GetGoogleEmbeddedIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGoogleEmbeddedIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p unauthorized response has a 2xx status code
func (o *GetGoogleEmbeddedIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p unauthorized response has a 3xx status code
func (o *GetGoogleEmbeddedIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p unauthorized response has a 4xx status code
func (o *GetGoogleEmbeddedIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p unauthorized response has a 5xx status code
func (o *GetGoogleEmbeddedIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p unauthorized response a status code equal to that given
func (o *GetGoogleEmbeddedIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get google embedded Id p unauthorized response
func (o *GetGoogleEmbeddedIDPUnauthorized) Code() int {
	return 401
}

func (o *GetGoogleEmbeddedIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGoogleEmbeddedIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGoogleEmbeddedIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPForbidden creates a GetGoogleEmbeddedIDPForbidden with default headers values
func NewGetGoogleEmbeddedIDPForbidden() *GetGoogleEmbeddedIDPForbidden {
	return &GetGoogleEmbeddedIDPForbidden{}
}

/*
GetGoogleEmbeddedIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetGoogleEmbeddedIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p forbidden response has a 2xx status code
func (o *GetGoogleEmbeddedIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p forbidden response has a 3xx status code
func (o *GetGoogleEmbeddedIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p forbidden response has a 4xx status code
func (o *GetGoogleEmbeddedIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p forbidden response has a 5xx status code
func (o *GetGoogleEmbeddedIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p forbidden response a status code equal to that given
func (o *GetGoogleEmbeddedIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get google embedded Id p forbidden response
func (o *GetGoogleEmbeddedIDPForbidden) Code() int {
	return 403
}

func (o *GetGoogleEmbeddedIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetGoogleEmbeddedIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetGoogleEmbeddedIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPNotFound creates a GetGoogleEmbeddedIDPNotFound with default headers values
func NewGetGoogleEmbeddedIDPNotFound() *GetGoogleEmbeddedIDPNotFound {
	return &GetGoogleEmbeddedIDPNotFound{}
}

/*
GetGoogleEmbeddedIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetGoogleEmbeddedIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p not found response has a 2xx status code
func (o *GetGoogleEmbeddedIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p not found response has a 3xx status code
func (o *GetGoogleEmbeddedIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p not found response has a 4xx status code
func (o *GetGoogleEmbeddedIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p not found response has a 5xx status code
func (o *GetGoogleEmbeddedIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p not found response a status code equal to that given
func (o *GetGoogleEmbeddedIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get google embedded Id p not found response
func (o *GetGoogleEmbeddedIDPNotFound) Code() int {
	return 404
}

func (o *GetGoogleEmbeddedIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetGoogleEmbeddedIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetGoogleEmbeddedIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPTooManyRequests creates a GetGoogleEmbeddedIDPTooManyRequests with default headers values
func NewGetGoogleEmbeddedIDPTooManyRequests() *GetGoogleEmbeddedIDPTooManyRequests {
	return &GetGoogleEmbeddedIDPTooManyRequests{}
}

/*
GetGoogleEmbeddedIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetGoogleEmbeddedIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p too many requests response has a 2xx status code
func (o *GetGoogleEmbeddedIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p too many requests response has a 3xx status code
func (o *GetGoogleEmbeddedIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p too many requests response has a 4xx status code
func (o *GetGoogleEmbeddedIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p too many requests response has a 5xx status code
func (o *GetGoogleEmbeddedIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p too many requests response a status code equal to that given
func (o *GetGoogleEmbeddedIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get google embedded Id p too many requests response
func (o *GetGoogleEmbeddedIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetGoogleEmbeddedIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGoogleEmbeddedIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}][%d] getGoogleEmbeddedIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGoogleEmbeddedIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
