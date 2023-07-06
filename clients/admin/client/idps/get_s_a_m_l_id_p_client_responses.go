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

// GetSAMLIDPClientReader is a Reader for the GetSAMLIDPClient structure.
type GetSAMLIDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetSAMLIDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetSAMLIDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetSAMLIDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetSAMLIDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetSAMLIDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetSAMLIDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetSAMLIDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/saml/{iid}/client] getSAMLIDPClient", response, response.Code())
	}
}

// NewGetSAMLIDPClientOK creates a GetSAMLIDPClientOK with default headers values
func NewGetSAMLIDPClientOK() *GetSAMLIDPClientOK {
	return &GetSAMLIDPClientOK{}
}

/*
GetSAMLIDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetSAMLIDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get s a m l Id p client o k response has a 2xx status code
func (o *GetSAMLIDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get s a m l Id p client o k response has a 3xx status code
func (o *GetSAMLIDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client o k response has a 4xx status code
func (o *GetSAMLIDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get s a m l Id p client o k response has a 5xx status code
func (o *GetSAMLIDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client o k response a status code equal to that given
func (o *GetSAMLIDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get s a m l Id p client o k response
func (o *GetSAMLIDPClientOK) Code() int {
	return 200
}

func (o *GetSAMLIDPClientOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientOK  %+v", 200, o.Payload)
}

func (o *GetSAMLIDPClientOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientOK  %+v", 200, o.Payload)
}

func (o *GetSAMLIDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetSAMLIDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ClientAdminResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSAMLIDPClientBadRequest creates a GetSAMLIDPClientBadRequest with default headers values
func NewGetSAMLIDPClientBadRequest() *GetSAMLIDPClientBadRequest {
	return &GetSAMLIDPClientBadRequest{}
}

/*
GetSAMLIDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetSAMLIDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get s a m l Id p client bad request response has a 2xx status code
func (o *GetSAMLIDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get s a m l Id p client bad request response has a 3xx status code
func (o *GetSAMLIDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client bad request response has a 4xx status code
func (o *GetSAMLIDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get s a m l Id p client bad request response has a 5xx status code
func (o *GetSAMLIDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client bad request response a status code equal to that given
func (o *GetSAMLIDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get s a m l Id p client bad request response
func (o *GetSAMLIDPClientBadRequest) Code() int {
	return 400
}

func (o *GetSAMLIDPClientBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientBadRequest  %+v", 400, o.Payload)
}

func (o *GetSAMLIDPClientBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientBadRequest  %+v", 400, o.Payload)
}

func (o *GetSAMLIDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSAMLIDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSAMLIDPClientUnauthorized creates a GetSAMLIDPClientUnauthorized with default headers values
func NewGetSAMLIDPClientUnauthorized() *GetSAMLIDPClientUnauthorized {
	return &GetSAMLIDPClientUnauthorized{}
}

/*
GetSAMLIDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetSAMLIDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get s a m l Id p client unauthorized response has a 2xx status code
func (o *GetSAMLIDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get s a m l Id p client unauthorized response has a 3xx status code
func (o *GetSAMLIDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client unauthorized response has a 4xx status code
func (o *GetSAMLIDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get s a m l Id p client unauthorized response has a 5xx status code
func (o *GetSAMLIDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client unauthorized response a status code equal to that given
func (o *GetSAMLIDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get s a m l Id p client unauthorized response
func (o *GetSAMLIDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetSAMLIDPClientUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetSAMLIDPClientUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetSAMLIDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSAMLIDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSAMLIDPClientForbidden creates a GetSAMLIDPClientForbidden with default headers values
func NewGetSAMLIDPClientForbidden() *GetSAMLIDPClientForbidden {
	return &GetSAMLIDPClientForbidden{}
}

/*
GetSAMLIDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetSAMLIDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get s a m l Id p client forbidden response has a 2xx status code
func (o *GetSAMLIDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get s a m l Id p client forbidden response has a 3xx status code
func (o *GetSAMLIDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client forbidden response has a 4xx status code
func (o *GetSAMLIDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get s a m l Id p client forbidden response has a 5xx status code
func (o *GetSAMLIDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client forbidden response a status code equal to that given
func (o *GetSAMLIDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get s a m l Id p client forbidden response
func (o *GetSAMLIDPClientForbidden) Code() int {
	return 403
}

func (o *GetSAMLIDPClientForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientForbidden  %+v", 403, o.Payload)
}

func (o *GetSAMLIDPClientForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientForbidden  %+v", 403, o.Payload)
}

func (o *GetSAMLIDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSAMLIDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSAMLIDPClientNotFound creates a GetSAMLIDPClientNotFound with default headers values
func NewGetSAMLIDPClientNotFound() *GetSAMLIDPClientNotFound {
	return &GetSAMLIDPClientNotFound{}
}

/*
GetSAMLIDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetSAMLIDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get s a m l Id p client not found response has a 2xx status code
func (o *GetSAMLIDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get s a m l Id p client not found response has a 3xx status code
func (o *GetSAMLIDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client not found response has a 4xx status code
func (o *GetSAMLIDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get s a m l Id p client not found response has a 5xx status code
func (o *GetSAMLIDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client not found response a status code equal to that given
func (o *GetSAMLIDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get s a m l Id p client not found response
func (o *GetSAMLIDPClientNotFound) Code() int {
	return 404
}

func (o *GetSAMLIDPClientNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientNotFound  %+v", 404, o.Payload)
}

func (o *GetSAMLIDPClientNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientNotFound  %+v", 404, o.Payload)
}

func (o *GetSAMLIDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSAMLIDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetSAMLIDPClientTooManyRequests creates a GetSAMLIDPClientTooManyRequests with default headers values
func NewGetSAMLIDPClientTooManyRequests() *GetSAMLIDPClientTooManyRequests {
	return &GetSAMLIDPClientTooManyRequests{}
}

/*
GetSAMLIDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetSAMLIDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get s a m l Id p client too many requests response has a 2xx status code
func (o *GetSAMLIDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get s a m l Id p client too many requests response has a 3xx status code
func (o *GetSAMLIDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get s a m l Id p client too many requests response has a 4xx status code
func (o *GetSAMLIDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get s a m l Id p client too many requests response has a 5xx status code
func (o *GetSAMLIDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get s a m l Id p client too many requests response a status code equal to that given
func (o *GetSAMLIDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get s a m l Id p client too many requests response
func (o *GetSAMLIDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetSAMLIDPClientTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSAMLIDPClientTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/saml/{iid}/client][%d] getSAMLIdPClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetSAMLIDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetSAMLIDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
