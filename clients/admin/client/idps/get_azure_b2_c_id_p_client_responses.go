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

// GetAzureB2CIDPClientReader is a Reader for the GetAzureB2CIDPClient structure.
type GetAzureB2CIDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAzureB2CIDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAzureB2CIDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAzureB2CIDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAzureB2CIDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAzureB2CIDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetAzureB2CIDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAzureB2CIDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/azureb2c/{iid}/client] getAzureB2CIDPClient", response, response.Code())
	}
}

// NewGetAzureB2CIDPClientOK creates a GetAzureB2CIDPClientOK with default headers values
func NewGetAzureB2CIDPClientOK() *GetAzureB2CIDPClientOK {
	return &GetAzureB2CIDPClientOK{}
}

/*
GetAzureB2CIDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetAzureB2CIDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get azure b2 c Id p client o k response has a 2xx status code
func (o *GetAzureB2CIDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get azure b2 c Id p client o k response has a 3xx status code
func (o *GetAzureB2CIDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client o k response has a 4xx status code
func (o *GetAzureB2CIDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get azure b2 c Id p client o k response has a 5xx status code
func (o *GetAzureB2CIDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client o k response a status code equal to that given
func (o *GetAzureB2CIDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get azure b2 c Id p client o k response
func (o *GetAzureB2CIDPClientOK) Code() int {
	return 200
}

func (o *GetAzureB2CIDPClientOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientOK %s", 200, payload)
}

func (o *GetAzureB2CIDPClientOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientOK %s", 200, payload)
}

func (o *GetAzureB2CIDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetAzureB2CIDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetAzureB2CIDPClientBadRequest creates a GetAzureB2CIDPClientBadRequest with default headers values
func NewGetAzureB2CIDPClientBadRequest() *GetAzureB2CIDPClientBadRequest {
	return &GetAzureB2CIDPClientBadRequest{}
}

/*
GetAzureB2CIDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetAzureB2CIDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get azure b2 c Id p client bad request response has a 2xx status code
func (o *GetAzureB2CIDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get azure b2 c Id p client bad request response has a 3xx status code
func (o *GetAzureB2CIDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client bad request response has a 4xx status code
func (o *GetAzureB2CIDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get azure b2 c Id p client bad request response has a 5xx status code
func (o *GetAzureB2CIDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client bad request response a status code equal to that given
func (o *GetAzureB2CIDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get azure b2 c Id p client bad request response
func (o *GetAzureB2CIDPClientBadRequest) Code() int {
	return 400
}

func (o *GetAzureB2CIDPClientBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientBadRequest %s", 400, payload)
}

func (o *GetAzureB2CIDPClientBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientBadRequest %s", 400, payload)
}

func (o *GetAzureB2CIDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPClientUnauthorized creates a GetAzureB2CIDPClientUnauthorized with default headers values
func NewGetAzureB2CIDPClientUnauthorized() *GetAzureB2CIDPClientUnauthorized {
	return &GetAzureB2CIDPClientUnauthorized{}
}

/*
GetAzureB2CIDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAzureB2CIDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get azure b2 c Id p client unauthorized response has a 2xx status code
func (o *GetAzureB2CIDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get azure b2 c Id p client unauthorized response has a 3xx status code
func (o *GetAzureB2CIDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client unauthorized response has a 4xx status code
func (o *GetAzureB2CIDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get azure b2 c Id p client unauthorized response has a 5xx status code
func (o *GetAzureB2CIDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client unauthorized response a status code equal to that given
func (o *GetAzureB2CIDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get azure b2 c Id p client unauthorized response
func (o *GetAzureB2CIDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetAzureB2CIDPClientUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientUnauthorized %s", 401, payload)
}

func (o *GetAzureB2CIDPClientUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientUnauthorized %s", 401, payload)
}

func (o *GetAzureB2CIDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPClientForbidden creates a GetAzureB2CIDPClientForbidden with default headers values
func NewGetAzureB2CIDPClientForbidden() *GetAzureB2CIDPClientForbidden {
	return &GetAzureB2CIDPClientForbidden{}
}

/*
GetAzureB2CIDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAzureB2CIDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get azure b2 c Id p client forbidden response has a 2xx status code
func (o *GetAzureB2CIDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get azure b2 c Id p client forbidden response has a 3xx status code
func (o *GetAzureB2CIDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client forbidden response has a 4xx status code
func (o *GetAzureB2CIDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get azure b2 c Id p client forbidden response has a 5xx status code
func (o *GetAzureB2CIDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client forbidden response a status code equal to that given
func (o *GetAzureB2CIDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get azure b2 c Id p client forbidden response
func (o *GetAzureB2CIDPClientForbidden) Code() int {
	return 403
}

func (o *GetAzureB2CIDPClientForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientForbidden %s", 403, payload)
}

func (o *GetAzureB2CIDPClientForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientForbidden %s", 403, payload)
}

func (o *GetAzureB2CIDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPClientNotFound creates a GetAzureB2CIDPClientNotFound with default headers values
func NewGetAzureB2CIDPClientNotFound() *GetAzureB2CIDPClientNotFound {
	return &GetAzureB2CIDPClientNotFound{}
}

/*
GetAzureB2CIDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetAzureB2CIDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get azure b2 c Id p client not found response has a 2xx status code
func (o *GetAzureB2CIDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get azure b2 c Id p client not found response has a 3xx status code
func (o *GetAzureB2CIDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client not found response has a 4xx status code
func (o *GetAzureB2CIDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get azure b2 c Id p client not found response has a 5xx status code
func (o *GetAzureB2CIDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client not found response a status code equal to that given
func (o *GetAzureB2CIDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get azure b2 c Id p client not found response
func (o *GetAzureB2CIDPClientNotFound) Code() int {
	return 404
}

func (o *GetAzureB2CIDPClientNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientNotFound %s", 404, payload)
}

func (o *GetAzureB2CIDPClientNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientNotFound %s", 404, payload)
}

func (o *GetAzureB2CIDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAzureB2CIDPClientTooManyRequests creates a GetAzureB2CIDPClientTooManyRequests with default headers values
func NewGetAzureB2CIDPClientTooManyRequests() *GetAzureB2CIDPClientTooManyRequests {
	return &GetAzureB2CIDPClientTooManyRequests{}
}

/*
GetAzureB2CIDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetAzureB2CIDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get azure b2 c Id p client too many requests response has a 2xx status code
func (o *GetAzureB2CIDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get azure b2 c Id p client too many requests response has a 3xx status code
func (o *GetAzureB2CIDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get azure b2 c Id p client too many requests response has a 4xx status code
func (o *GetAzureB2CIDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get azure b2 c Id p client too many requests response has a 5xx status code
func (o *GetAzureB2CIDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get azure b2 c Id p client too many requests response a status code equal to that given
func (o *GetAzureB2CIDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get azure b2 c Id p client too many requests response
func (o *GetAzureB2CIDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetAzureB2CIDPClientTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetAzureB2CIDPClientTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/azureb2c/{iid}/client][%d] getAzureB2CIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetAzureB2CIDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetAzureB2CIDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
