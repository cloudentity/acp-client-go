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

// GetGoogleEmbeddedIDPClientReader is a Reader for the GetGoogleEmbeddedIDPClient structure.
type GetGoogleEmbeddedIDPClientReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGoogleEmbeddedIDPClientReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGoogleEmbeddedIDPClientOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetGoogleEmbeddedIDPClientBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetGoogleEmbeddedIDPClientUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGoogleEmbeddedIDPClientForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGoogleEmbeddedIDPClientNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetGoogleEmbeddedIDPClientTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/google_embedded/{iid}/client] getGoogleEmbeddedIDPClient", response, response.Code())
	}
}

// NewGetGoogleEmbeddedIDPClientOK creates a GetGoogleEmbeddedIDPClientOK with default headers values
func NewGetGoogleEmbeddedIDPClientOK() *GetGoogleEmbeddedIDPClientOK {
	return &GetGoogleEmbeddedIDPClientOK{}
}

/*
GetGoogleEmbeddedIDPClientOK describes a response with status code 200, with default header values.

Client
*/
type GetGoogleEmbeddedIDPClientOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientAdminResponse
}

// IsSuccess returns true when this get google embedded Id p client o k response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get google embedded Id p client o k response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client o k response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get google embedded Id p client o k response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client o k response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get google embedded Id p client o k response
func (o *GetGoogleEmbeddedIDPClientOK) Code() int {
	return 200
}

func (o *GetGoogleEmbeddedIDPClientOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientOK %s", 200, payload)
}

func (o *GetGoogleEmbeddedIDPClientOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientOK %s", 200, payload)
}

func (o *GetGoogleEmbeddedIDPClientOK) GetPayload() *models.ClientAdminResponse {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetGoogleEmbeddedIDPClientBadRequest creates a GetGoogleEmbeddedIDPClientBadRequest with default headers values
func NewGetGoogleEmbeddedIDPClientBadRequest() *GetGoogleEmbeddedIDPClientBadRequest {
	return &GetGoogleEmbeddedIDPClientBadRequest{}
}

/*
GetGoogleEmbeddedIDPClientBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetGoogleEmbeddedIDPClientBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p client bad request response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p client bad request response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client bad request response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p client bad request response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client bad request response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get google embedded Id p client bad request response
func (o *GetGoogleEmbeddedIDPClientBadRequest) Code() int {
	return 400
}

func (o *GetGoogleEmbeddedIDPClientBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientBadRequest %s", 400, payload)
}

func (o *GetGoogleEmbeddedIDPClientBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientBadRequest %s", 400, payload)
}

func (o *GetGoogleEmbeddedIDPClientBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPClientUnauthorized creates a GetGoogleEmbeddedIDPClientUnauthorized with default headers values
func NewGetGoogleEmbeddedIDPClientUnauthorized() *GetGoogleEmbeddedIDPClientUnauthorized {
	return &GetGoogleEmbeddedIDPClientUnauthorized{}
}

/*
GetGoogleEmbeddedIDPClientUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGoogleEmbeddedIDPClientUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p client unauthorized response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p client unauthorized response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client unauthorized response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p client unauthorized response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client unauthorized response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get google embedded Id p client unauthorized response
func (o *GetGoogleEmbeddedIDPClientUnauthorized) Code() int {
	return 401
}

func (o *GetGoogleEmbeddedIDPClientUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientUnauthorized %s", 401, payload)
}

func (o *GetGoogleEmbeddedIDPClientUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientUnauthorized %s", 401, payload)
}

func (o *GetGoogleEmbeddedIDPClientUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPClientForbidden creates a GetGoogleEmbeddedIDPClientForbidden with default headers values
func NewGetGoogleEmbeddedIDPClientForbidden() *GetGoogleEmbeddedIDPClientForbidden {
	return &GetGoogleEmbeddedIDPClientForbidden{}
}

/*
GetGoogleEmbeddedIDPClientForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetGoogleEmbeddedIDPClientForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p client forbidden response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p client forbidden response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client forbidden response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p client forbidden response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client forbidden response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get google embedded Id p client forbidden response
func (o *GetGoogleEmbeddedIDPClientForbidden) Code() int {
	return 403
}

func (o *GetGoogleEmbeddedIDPClientForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientForbidden %s", 403, payload)
}

func (o *GetGoogleEmbeddedIDPClientForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientForbidden %s", 403, payload)
}

func (o *GetGoogleEmbeddedIDPClientForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPClientNotFound creates a GetGoogleEmbeddedIDPClientNotFound with default headers values
func NewGetGoogleEmbeddedIDPClientNotFound() *GetGoogleEmbeddedIDPClientNotFound {
	return &GetGoogleEmbeddedIDPClientNotFound{}
}

/*
GetGoogleEmbeddedIDPClientNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetGoogleEmbeddedIDPClientNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p client not found response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p client not found response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client not found response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p client not found response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client not found response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get google embedded Id p client not found response
func (o *GetGoogleEmbeddedIDPClientNotFound) Code() int {
	return 404
}

func (o *GetGoogleEmbeddedIDPClientNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientNotFound %s", 404, payload)
}

func (o *GetGoogleEmbeddedIDPClientNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientNotFound %s", 404, payload)
}

func (o *GetGoogleEmbeddedIDPClientNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGoogleEmbeddedIDPClientTooManyRequests creates a GetGoogleEmbeddedIDPClientTooManyRequests with default headers values
func NewGetGoogleEmbeddedIDPClientTooManyRequests() *GetGoogleEmbeddedIDPClientTooManyRequests {
	return &GetGoogleEmbeddedIDPClientTooManyRequests{}
}

/*
GetGoogleEmbeddedIDPClientTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetGoogleEmbeddedIDPClientTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get google embedded Id p client too many requests response has a 2xx status code
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get google embedded Id p client too many requests response has a 3xx status code
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get google embedded Id p client too many requests response has a 4xx status code
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get google embedded Id p client too many requests response has a 5xx status code
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get google embedded Id p client too many requests response a status code equal to that given
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get google embedded Id p client too many requests response
func (o *GetGoogleEmbeddedIDPClientTooManyRequests) Code() int {
	return 429
}

func (o *GetGoogleEmbeddedIDPClientTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetGoogleEmbeddedIDPClientTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /servers/{wid}/idps/google_embedded/{iid}/client][%d] getGoogleEmbeddedIdPClientTooManyRequests %s", 429, payload)
}

func (o *GetGoogleEmbeddedIDPClientTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGoogleEmbeddedIDPClientTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
