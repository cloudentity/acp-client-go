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

// GetStaticIDPClientReader is a Reader for the GetStaticIDPClient structure.
type GetStaticIDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetStaticIDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetStaticIDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetStaticIDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetStaticIDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetStaticIDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetStaticIDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetStaticIDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/static/{iid}/client] getStaticIDPClient", response, response.Code())
	}
}

// NewGetStaticIDPClientOK creates a GetStaticIDPClientOK with default headers values
func NewGetStaticIDPClientOK() *GetStaticIDPClientOK {
	return &GetStaticIDPClientOK{}
}

/*
GetStaticIDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetStaticIDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get static Id p client o k response has a 2xx status code
func (o *GetStaticIDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get static Id p client o k response has a 3xx status code
func (o *GetStaticIDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client o k response has a 4xx status code
func (o *GetStaticIDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get static Id p client o k response has a 5xx status code
func (o *GetStaticIDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client o k response a status code equal to that given
func (o *GetStaticIDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get static Id p client o k response
func (o *GetStaticIDPClientOK) Code() int {
	return 200
}

func (o *GetStaticIDPClientOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientOK %s", 200, payload)
}

func (o *GetStaticIDPClientOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientOK %s", 200, payload)
}

func (o *GetStaticIDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetStaticIDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetStaticIDPClientBadRequest creates a GetStaticIDPClientBadRequest with default headers values
func NewGetStaticIDPClientBadRequest() *GetStaticIDPClientBadRequest {
	return &GetStaticIDPClientBadRequest{}
}

/*
GetStaticIDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetStaticIDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p client bad request response has a 2xx status code
func (o *GetStaticIDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p client bad request response has a 3xx status code
func (o *GetStaticIDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client bad request response has a 4xx status code
func (o *GetStaticIDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p client bad request response has a 5xx status code
func (o *GetStaticIDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client bad request response a status code equal to that given
func (o *GetStaticIDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get static Id p client bad request response
func (o *GetStaticIDPClientBadRequest) Code() int {
	return 400
}

func (o *GetStaticIDPClientBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientBadRequest %s", 400, payload)
}

func (o *GetStaticIDPClientBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientBadRequest %s", 400, payload)
}

func (o *GetStaticIDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPClientUnauthorized creates a GetStaticIDPClientUnauthorized with default headers values
func NewGetStaticIDPClientUnauthorized() *GetStaticIDPClientUnauthorized {
	return &GetStaticIDPClientUnauthorized{}
}

/*
GetStaticIDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetStaticIDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p client unauthorized response has a 2xx status code
func (o *GetStaticIDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p client unauthorized response has a 3xx status code
func (o *GetStaticIDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client unauthorized response has a 4xx status code
func (o *GetStaticIDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p client unauthorized response has a 5xx status code
func (o *GetStaticIDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client unauthorized response a status code equal to that given
func (o *GetStaticIDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get static Id p client unauthorized response
func (o *GetStaticIDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetStaticIDPClientUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientUnauthorized %s", 401, payload)
}

func (o *GetStaticIDPClientUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientUnauthorized %s", 401, payload)
}

func (o *GetStaticIDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPClientForbidden creates a GetStaticIDPClientForbidden with default headers values
func NewGetStaticIDPClientForbidden() *GetStaticIDPClientForbidden {
	return &GetStaticIDPClientForbidden{}
}

/*
GetStaticIDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetStaticIDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p client forbidden response has a 2xx status code
func (o *GetStaticIDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p client forbidden response has a 3xx status code
func (o *GetStaticIDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client forbidden response has a 4xx status code
func (o *GetStaticIDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p client forbidden response has a 5xx status code
func (o *GetStaticIDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client forbidden response a status code equal to that given
func (o *GetStaticIDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get static Id p client forbidden response
func (o *GetStaticIDPClientForbidden) Code() int {
	return 403
}

func (o *GetStaticIDPClientForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientForbidden %s", 403, payload)
}

func (o *GetStaticIDPClientForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientForbidden %s", 403, payload)
}

func (o *GetStaticIDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPClientNotFound creates a GetStaticIDPClientNotFound with default headers values
func NewGetStaticIDPClientNotFound() *GetStaticIDPClientNotFound {
	return &GetStaticIDPClientNotFound{}
}

/*
GetStaticIDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetStaticIDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p client not found response has a 2xx status code
func (o *GetStaticIDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p client not found response has a 3xx status code
func (o *GetStaticIDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client not found response has a 4xx status code
func (o *GetStaticIDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p client not found response has a 5xx status code
func (o *GetStaticIDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client not found response a status code equal to that given
func (o *GetStaticIDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get static Id p client not found response
func (o *GetStaticIDPClientNotFound) Code() int {
	return 404
}

func (o *GetStaticIDPClientNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientNotFound %s", 404, payload)
}

func (o *GetStaticIDPClientNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientNotFound %s", 404, payload)
}

func (o *GetStaticIDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetStaticIDPClientTooManyRequests creates a GetStaticIDPClientTooManyRequests with default headers values
func NewGetStaticIDPClientTooManyRequests() *GetStaticIDPClientTooManyRequests {
	return &GetStaticIDPClientTooManyRequests{}
}

/*
GetStaticIDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetStaticIDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get static Id p client too many requests response has a 2xx status code
func (o *GetStaticIDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get static Id p client too many requests response has a 3xx status code
func (o *GetStaticIDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get static Id p client too many requests response has a 4xx status code
func (o *GetStaticIDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get static Id p client too many requests response has a 5xx status code
func (o *GetStaticIDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get static Id p client too many requests response a status code equal to that given
func (o *GetStaticIDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get static Id p client too many requests response
func (o *GetStaticIDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetStaticIDPClientTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetStaticIDPClientTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/static/{iid}/client][%d] getStaticIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetStaticIDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetStaticIDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
