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

// GetAuth0IDPClientReader is a Reader for the GetAuth0IDPClient structure.
type GetAuth0IDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAuth0IDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAuth0IDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAuth0IDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAuth0IDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAuth0IDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAuth0IDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAuth0IDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/auth0/{iid}/client] getAuth0IDPClient", response, response.Code())
	}
}

// NewGetAuth0IDPClientOK creates a GetAuth0IDPClientOK with default headers values
func NewGetAuth0IDPClientOK() *GetAuth0IDPClientOK {
	return &GetAuth0IDPClientOK{}
}

/*
GetAuth0IDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetAuth0IDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get auth0 Id p client o k response has a 2xx status code
func (o *GetAuth0IDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get auth0 Id p client o k response has a 3xx status code
func (o *GetAuth0IDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client o k response has a 4xx status code
func (o *GetAuth0IDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get auth0 Id p client o k response has a 5xx status code
func (o *GetAuth0IDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client o k response a status code equal to that given
func (o *GetAuth0IDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get auth0 Id p client o k response
func (o *GetAuth0IDPClientOK) Code() int {
	return 200
}

func (o *GetAuth0IDPClientOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientOK  %+v", 200, o.Payload)
}

func (o *GetAuth0IDPClientOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientOK  %+v", 200, o.Payload)
}

func (o *GetAuth0IDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetAuth0IDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetAuth0IDPClientBadRequest creates a GetAuth0IDPClientBadRequest with default headers values
func NewGetAuth0IDPClientBadRequest() *GetAuth0IDPClientBadRequest {
	return &GetAuth0IDPClientBadRequest{}
}

/*
GetAuth0IDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetAuth0IDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get auth0 Id p client bad request response has a 2xx status code
func (o *GetAuth0IDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get auth0 Id p client bad request response has a 3xx status code
func (o *GetAuth0IDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client bad request response has a 4xx status code
func (o *GetAuth0IDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get auth0 Id p client bad request response has a 5xx status code
func (o *GetAuth0IDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client bad request response a status code equal to that given
func (o *GetAuth0IDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get auth0 Id p client bad request response
func (o *GetAuth0IDPClientBadRequest) Code() int {
	return 400
}

func (o *GetAuth0IDPClientBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientBadRequest  %+v", 400, o.Payload)
}

func (o *GetAuth0IDPClientBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientBadRequest  %+v", 400, o.Payload)
}

func (o *GetAuth0IDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuth0IDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuth0IDPClientUnauthorized creates a GetAuth0IDPClientUnauthorized with default headers values
func NewGetAuth0IDPClientUnauthorized() *GetAuth0IDPClientUnauthorized {
	return &GetAuth0IDPClientUnauthorized{}
}

/*
GetAuth0IDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAuth0IDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get auth0 Id p client unauthorized response has a 2xx status code
func (o *GetAuth0IDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get auth0 Id p client unauthorized response has a 3xx status code
func (o *GetAuth0IDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client unauthorized response has a 4xx status code
func (o *GetAuth0IDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get auth0 Id p client unauthorized response has a 5xx status code
func (o *GetAuth0IDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client unauthorized response a status code equal to that given
func (o *GetAuth0IDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get auth0 Id p client unauthorized response
func (o *GetAuth0IDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetAuth0IDPClientUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAuth0IDPClientUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientUnauthorized  %+v", 401, o.Payload)
}

func (o *GetAuth0IDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuth0IDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuth0IDPClientForbidden creates a GetAuth0IDPClientForbidden with default headers values
func NewGetAuth0IDPClientForbidden() *GetAuth0IDPClientForbidden {
	return &GetAuth0IDPClientForbidden{}
}

/*
GetAuth0IDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAuth0IDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get auth0 Id p client forbidden response has a 2xx status code
func (o *GetAuth0IDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get auth0 Id p client forbidden response has a 3xx status code
func (o *GetAuth0IDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client forbidden response has a 4xx status code
func (o *GetAuth0IDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get auth0 Id p client forbidden response has a 5xx status code
func (o *GetAuth0IDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client forbidden response a status code equal to that given
func (o *GetAuth0IDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get auth0 Id p client forbidden response
func (o *GetAuth0IDPClientForbidden) Code() int {
	return 403
}

func (o *GetAuth0IDPClientForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientForbidden  %+v", 403, o.Payload)
}

func (o *GetAuth0IDPClientForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientForbidden  %+v", 403, o.Payload)
}

func (o *GetAuth0IDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuth0IDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuth0IDPClientNotFound creates a GetAuth0IDPClientNotFound with default headers values
func NewGetAuth0IDPClientNotFound() *GetAuth0IDPClientNotFound {
	return &GetAuth0IDPClientNotFound{}
}

/*
GetAuth0IDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAuth0IDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get auth0 Id p client not found response has a 2xx status code
func (o *GetAuth0IDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get auth0 Id p client not found response has a 3xx status code
func (o *GetAuth0IDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client not found response has a 4xx status code
func (o *GetAuth0IDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get auth0 Id p client not found response has a 5xx status code
func (o *GetAuth0IDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client not found response a status code equal to that given
func (o *GetAuth0IDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get auth0 Id p client not found response
func (o *GetAuth0IDPClientNotFound) Code() int {
	return 404
}

func (o *GetAuth0IDPClientNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientNotFound  %+v", 404, o.Payload)
}

func (o *GetAuth0IDPClientNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientNotFound  %+v", 404, o.Payload)
}

func (o *GetAuth0IDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuth0IDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAuth0IDPClientTooManyRequests creates a GetAuth0IDPClientTooManyRequests with default headers values
func NewGetAuth0IDPClientTooManyRequests() *GetAuth0IDPClientTooManyRequests {
	return &GetAuth0IDPClientTooManyRequests{}
}

/*
GetAuth0IDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetAuth0IDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get auth0 Id p client too many requests response has a 2xx status code
func (o *GetAuth0IDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get auth0 Id p client too many requests response has a 3xx status code
func (o *GetAuth0IDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get auth0 Id p client too many requests response has a 4xx status code
func (o *GetAuth0IDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get auth0 Id p client too many requests response has a 5xx status code
func (o *GetAuth0IDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get auth0 Id p client too many requests response a status code equal to that given
func (o *GetAuth0IDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get auth0 Id p client too many requests response
func (o *GetAuth0IDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetAuth0IDPClientTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAuth0IDPClientTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/auth0/{iid}/client][%d] getAuth0IdPClientTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetAuth0IDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAuth0IDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
