// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// GetGoogleIDPClientReader is a Reader for the GetGoogleIDPClient structure.
type GetGoogleIDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGoogleIDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGoogleIDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetGoogleIDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetGoogleIDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGoogleIDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGoogleIDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetGoogleIDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/google/{iid}/client] getGoogleIDPClient", response, response.Code())
	}
}

// NewGetGoogleIDPClientOK creates a GetGoogleIDPClientOK with default headers values
func NewGetGoogleIDPClientOK() *GetGoogleIDPClientOK {
	return &GetGoogleIDPClientOK{}
}

/*
GetGoogleIDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetGoogleIDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get google Id p client o k response has a 2xx status code
func (o *GetGoogleIDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get google Id p client o k response has a 3xx status code
func (o *GetGoogleIDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client o k response has a 4xx status code
func (o *GetGoogleIDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get google Id p client o k response has a 5xx status code
func (o *GetGoogleIDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client o k response a status code equal to that given
func (o *GetGoogleIDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get google Id p client o k response
func (o *GetGoogleIDPClientOK) Code() int {
	return 200
}

func (o *GetGoogleIDPClientOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientOK %s", 200, payload)
}

func (o *GetGoogleIDPClientOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientOK %s", 200, payload)
}

func (o *GetGoogleIDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetGoogleIDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetGoogleIDPClientBadRequest creates a GetGoogleIDPClientBadRequest with default headers values
func NewGetGoogleIDPClientBadRequest() *GetGoogleIDPClientBadRequest {
	return &GetGoogleIDPClientBadRequest{}
}

/*
GetGoogleIDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetGoogleIDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google Id p client bad request response has a 2xx status code
func (o *GetGoogleIDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google Id p client bad request response has a 3xx status code
func (o *GetGoogleIDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client bad request response has a 4xx status code
func (o *GetGoogleIDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google Id p client bad request response has a 5xx status code
func (o *GetGoogleIDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client bad request response a status code equal to that given
func (o *GetGoogleIDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get google Id p client bad request response
func (o *GetGoogleIDPClientBadRequest) Code() int {
	return 400
}

func (o *GetGoogleIDPClientBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientBadRequest %s", 400, payload)
}

func (o *GetGoogleIDPClientBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientBadRequest %s", 400, payload)
}

func (o *GetGoogleIDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleIDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleIDPClientUnauthorized creates a GetGoogleIDPClientUnauthorized with default headers values
func NewGetGoogleIDPClientUnauthorized() *GetGoogleIDPClientUnauthorized {
	return &GetGoogleIDPClientUnauthorized{}
}

/*
GetGoogleIDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGoogleIDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google Id p client unauthorized response has a 2xx status code
func (o *GetGoogleIDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google Id p client unauthorized response has a 3xx status code
func (o *GetGoogleIDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client unauthorized response has a 4xx status code
func (o *GetGoogleIDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google Id p client unauthorized response has a 5xx status code
func (o *GetGoogleIDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client unauthorized response a status code equal to that given
func (o *GetGoogleIDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get google Id p client unauthorized response
func (o *GetGoogleIDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetGoogleIDPClientUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientUnauthorized %s", 401, payload)
}

func (o *GetGoogleIDPClientUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientUnauthorized %s", 401, payload)
}

func (o *GetGoogleIDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleIDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleIDPClientForbidden creates a GetGoogleIDPClientForbidden with default headers values
func NewGetGoogleIDPClientForbidden() *GetGoogleIDPClientForbidden {
	return &GetGoogleIDPClientForbidden{}
}

/*
GetGoogleIDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetGoogleIDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google Id p client forbidden response has a 2xx status code
func (o *GetGoogleIDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google Id p client forbidden response has a 3xx status code
func (o *GetGoogleIDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client forbidden response has a 4xx status code
func (o *GetGoogleIDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google Id p client forbidden response has a 5xx status code
func (o *GetGoogleIDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client forbidden response a status code equal to that given
func (o *GetGoogleIDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get google Id p client forbidden response
func (o *GetGoogleIDPClientForbidden) Code() int {
	return 403
}

func (o *GetGoogleIDPClientForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientForbidden %s", 403, payload)
}

func (o *GetGoogleIDPClientForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientForbidden %s", 403, payload)
}

func (o *GetGoogleIDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleIDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleIDPClientNotFound creates a GetGoogleIDPClientNotFound with default headers values
func NewGetGoogleIDPClientNotFound() *GetGoogleIDPClientNotFound {
	return &GetGoogleIDPClientNotFound{}
}

/*
GetGoogleIDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetGoogleIDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google Id p client not found response has a 2xx status code
func (o *GetGoogleIDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google Id p client not found response has a 3xx status code
func (o *GetGoogleIDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client not found response has a 4xx status code
func (o *GetGoogleIDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google Id p client not found response has a 5xx status code
func (o *GetGoogleIDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client not found response a status code equal to that given
func (o *GetGoogleIDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get google Id p client not found response
func (o *GetGoogleIDPClientNotFound) Code() int {
	return 404
}

func (o *GetGoogleIDPClientNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientNotFound %s", 404, payload)
}

func (o *GetGoogleIDPClientNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientNotFound %s", 404, payload)
}

func (o *GetGoogleIDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleIDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleIDPClientTooManyRequests creates a GetGoogleIDPClientTooManyRequests with default headers values
func NewGetGoogleIDPClientTooManyRequests() *GetGoogleIDPClientTooManyRequests {
	return &GetGoogleIDPClientTooManyRequests{}
}

/*
GetGoogleIDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetGoogleIDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google Id p client too many requests response has a 2xx status code
func (o *GetGoogleIDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google Id p client too many requests response has a 3xx status code
func (o *GetGoogleIDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google Id p client too many requests response has a 4xx status code
func (o *GetGoogleIDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google Id p client too many requests response has a 5xx status code
func (o *GetGoogleIDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get google Id p client too many requests response a status code equal to that given
func (o *GetGoogleIDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get google Id p client too many requests response
func (o *GetGoogleIDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetGoogleIDPClientTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetGoogleIDPClientTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google/{iid}/client][%d] getGoogleIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetGoogleIDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleIDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
