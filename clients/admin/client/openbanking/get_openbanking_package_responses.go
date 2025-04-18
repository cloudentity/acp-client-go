// Code generated by go-swagger; DO NOT EDIT.

package openbanking

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

// GetOpenbankingPackageReader is a Reader for the GetOpenbankingPackage structure.
type GetOpenbankingPackageReader struct {
	formats strfmt.Registry
	writer  io.Writer
}

// ReadResponse reads a server response into the received o.
func (o *GetOpenbankingPackageReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOpenbankingPackageOK(o.writer)
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetOpenbankingPackageBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetOpenbankingPackageUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOpenbankingPackageForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOpenbankingPackageNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOpenbankingPackageTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /openbanking/{wid}/package] getOpenbankingPackage", response, response.Code())
	}
}

// NewGetOpenbankingPackageOK creates a GetOpenbankingPackageOK with default headers values
func NewGetOpenbankingPackageOK(writer io.Writer) *GetOpenbankingPackageOK {
	return &GetOpenbankingPackageOK{

		Payload: writer,
	}
}

/*
GetOpenbankingPackageOK describes a response with status code 200, with default header values.

Openbanking package
*/
type GetOpenbankingPackageOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload io.Writer
}

// IsSuccess returns true when this get openbanking package o k response has a 2xx status code
func (o *GetOpenbankingPackageOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get openbanking package o k response has a 3xx status code
func (o *GetOpenbankingPackageOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package o k response has a 4xx status code
func (o *GetOpenbankingPackageOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get openbanking package o k response has a 5xx status code
func (o *GetOpenbankingPackageOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package o k response a status code equal to that given
func (o *GetOpenbankingPackageOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get openbanking package o k response
func (o *GetOpenbankingPackageOK) Code() int {
	return 200
}

func (o *GetOpenbankingPackageOK) Error() string {
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageOK", 200)
}

func (o *GetOpenbankingPackageOK) String() string {
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageOK", 200)
}

func (o *GetOpenbankingPackageOK) GetPayload() io.Writer {
	return o.Payload
}

func (o *GetOpenbankingPackageOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenbankingPackageBadRequest creates a GetOpenbankingPackageBadRequest with default headers values
func NewGetOpenbankingPackageBadRequest() *GetOpenbankingPackageBadRequest {
	return &GetOpenbankingPackageBadRequest{}
}

/*
GetOpenbankingPackageBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetOpenbankingPackageBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this get openbanking package bad request response has a 2xx status code
func (o *GetOpenbankingPackageBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get openbanking package bad request response has a 3xx status code
func (o *GetOpenbankingPackageBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package bad request response has a 4xx status code
func (o *GetOpenbankingPackageBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get openbanking package bad request response has a 5xx status code
func (o *GetOpenbankingPackageBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package bad request response a status code equal to that given
func (o *GetOpenbankingPackageBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get openbanking package bad request response
func (o *GetOpenbankingPackageBadRequest) Code() int {
	return 400
}

func (o *GetOpenbankingPackageBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageBadRequest %s", 400, payload)
}

func (o *GetOpenbankingPackageBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageBadRequest %s", 400, payload)
}

func (o *GetOpenbankingPackageBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOpenbankingPackageBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenbankingPackageUnauthorized creates a GetOpenbankingPackageUnauthorized with default headers values
func NewGetOpenbankingPackageUnauthorized() *GetOpenbankingPackageUnauthorized {
	return &GetOpenbankingPackageUnauthorized{}
}

/*
GetOpenbankingPackageUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetOpenbankingPackageUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get openbanking package unauthorized response has a 2xx status code
func (o *GetOpenbankingPackageUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get openbanking package unauthorized response has a 3xx status code
func (o *GetOpenbankingPackageUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package unauthorized response has a 4xx status code
func (o *GetOpenbankingPackageUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get openbanking package unauthorized response has a 5xx status code
func (o *GetOpenbankingPackageUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package unauthorized response a status code equal to that given
func (o *GetOpenbankingPackageUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get openbanking package unauthorized response
func (o *GetOpenbankingPackageUnauthorized) Code() int {
	return 401
}

func (o *GetOpenbankingPackageUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageUnauthorized %s", 401, payload)
}

func (o *GetOpenbankingPackageUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageUnauthorized %s", 401, payload)
}

func (o *GetOpenbankingPackageUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOpenbankingPackageUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenbankingPackageForbidden creates a GetOpenbankingPackageForbidden with default headers values
func NewGetOpenbankingPackageForbidden() *GetOpenbankingPackageForbidden {
	return &GetOpenbankingPackageForbidden{}
}

/*
GetOpenbankingPackageForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetOpenbankingPackageForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get openbanking package forbidden response has a 2xx status code
func (o *GetOpenbankingPackageForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get openbanking package forbidden response has a 3xx status code
func (o *GetOpenbankingPackageForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package forbidden response has a 4xx status code
func (o *GetOpenbankingPackageForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get openbanking package forbidden response has a 5xx status code
func (o *GetOpenbankingPackageForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package forbidden response a status code equal to that given
func (o *GetOpenbankingPackageForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get openbanking package forbidden response
func (o *GetOpenbankingPackageForbidden) Code() int {
	return 403
}

func (o *GetOpenbankingPackageForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageForbidden %s", 403, payload)
}

func (o *GetOpenbankingPackageForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageForbidden %s", 403, payload)
}

func (o *GetOpenbankingPackageForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOpenbankingPackageForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenbankingPackageNotFound creates a GetOpenbankingPackageNotFound with default headers values
func NewGetOpenbankingPackageNotFound() *GetOpenbankingPackageNotFound {
	return &GetOpenbankingPackageNotFound{}
}

/*
GetOpenbankingPackageNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetOpenbankingPackageNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get openbanking package not found response has a 2xx status code
func (o *GetOpenbankingPackageNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get openbanking package not found response has a 3xx status code
func (o *GetOpenbankingPackageNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package not found response has a 4xx status code
func (o *GetOpenbankingPackageNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get openbanking package not found response has a 5xx status code
func (o *GetOpenbankingPackageNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package not found response a status code equal to that given
func (o *GetOpenbankingPackageNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get openbanking package not found response
func (o *GetOpenbankingPackageNotFound) Code() int {
	return 404
}

func (o *GetOpenbankingPackageNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageNotFound %s", 404, payload)
}

func (o *GetOpenbankingPackageNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageNotFound %s", 404, payload)
}

func (o *GetOpenbankingPackageNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOpenbankingPackageNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOpenbankingPackageTooManyRequests creates a GetOpenbankingPackageTooManyRequests with default headers values
func NewGetOpenbankingPackageTooManyRequests() *GetOpenbankingPackageTooManyRequests {
	return &GetOpenbankingPackageTooManyRequests{}
}

/*
GetOpenbankingPackageTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetOpenbankingPackageTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get openbanking package too many requests response has a 2xx status code
func (o *GetOpenbankingPackageTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get openbanking package too many requests response has a 3xx status code
func (o *GetOpenbankingPackageTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get openbanking package too many requests response has a 4xx status code
func (o *GetOpenbankingPackageTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get openbanking package too many requests response has a 5xx status code
func (o *GetOpenbankingPackageTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get openbanking package too many requests response a status code equal to that given
func (o *GetOpenbankingPackageTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get openbanking package too many requests response
func (o *GetOpenbankingPackageTooManyRequests) Code() int {
	return 429
}

func (o *GetOpenbankingPackageTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageTooManyRequests %s", 429, payload)
}

func (o *GetOpenbankingPackageTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /openbanking/{wid}/package][%d] getOpenbankingPackageTooManyRequests %s", 429, payload)
}

func (o *GetOpenbankingPackageTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOpenbankingPackageTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
