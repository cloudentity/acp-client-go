// Code generated by go-swagger; DO NOT EDIT.

package scripts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// PatchScriptReader is a Reader for the PatchScript structure.
type PatchScriptReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchScriptReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchScriptOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchScriptBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchScriptUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchScriptForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchScriptNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchScriptTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /servers/{wid}/scripts/{script}] patchScript", response, response.Code())
	}
}

// NewPatchScriptOK creates a PatchScriptOK with default headers values
func NewPatchScriptOK() *PatchScriptOK {
	return &PatchScriptOK{}
}

/*
PatchScriptOK describes a response with status code 200, with default header values.

Script
*/
type PatchScriptOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.Script
}

// IsSuccess returns true when this patch script o k response has a 2xx status code
func (o *PatchScriptOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch script o k response has a 3xx status code
func (o *PatchScriptOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script o k response has a 4xx status code
func (o *PatchScriptOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch script o k response has a 5xx status code
func (o *PatchScriptOK) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script o k response a status code equal to that given
func (o *PatchScriptOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the patch script o k response
func (o *PatchScriptOK) Code() int {
	return 200
}

func (o *PatchScriptOK) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptOK  %+v", 200, o.Payload)
}

func (o *PatchScriptOK) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptOK  %+v", 200, o.Payload)
}

func (o *PatchScriptOK) GetPayload() *models.Script {
	return o.Payload
}

func (o *PatchScriptOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.Script)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchScriptBadRequest creates a PatchScriptBadRequest with default headers values
func NewPatchScriptBadRequest() *PatchScriptBadRequest {
	return &PatchScriptBadRequest{}
}

/*
PatchScriptBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type PatchScriptBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch script bad request response has a 2xx status code
func (o *PatchScriptBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch script bad request response has a 3xx status code
func (o *PatchScriptBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script bad request response has a 4xx status code
func (o *PatchScriptBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch script bad request response has a 5xx status code
func (o *PatchScriptBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script bad request response a status code equal to that given
func (o *PatchScriptBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the patch script bad request response
func (o *PatchScriptBadRequest) Code() int {
	return 400
}

func (o *PatchScriptBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptBadRequest  %+v", 400, o.Payload)
}

func (o *PatchScriptBadRequest) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptBadRequest  %+v", 400, o.Payload)
}

func (o *PatchScriptBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchScriptBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchScriptUnauthorized creates a PatchScriptUnauthorized with default headers values
func NewPatchScriptUnauthorized() *PatchScriptUnauthorized {
	return &PatchScriptUnauthorized{}
}

/*
PatchScriptUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PatchScriptUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch script unauthorized response has a 2xx status code
func (o *PatchScriptUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch script unauthorized response has a 3xx status code
func (o *PatchScriptUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script unauthorized response has a 4xx status code
func (o *PatchScriptUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch script unauthorized response has a 5xx status code
func (o *PatchScriptUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script unauthorized response a status code equal to that given
func (o *PatchScriptUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the patch script unauthorized response
func (o *PatchScriptUnauthorized) Code() int {
	return 401
}

func (o *PatchScriptUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchScriptUnauthorized) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchScriptUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchScriptUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchScriptForbidden creates a PatchScriptForbidden with default headers values
func NewPatchScriptForbidden() *PatchScriptForbidden {
	return &PatchScriptForbidden{}
}

/*
PatchScriptForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PatchScriptForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch script forbidden response has a 2xx status code
func (o *PatchScriptForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch script forbidden response has a 3xx status code
func (o *PatchScriptForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script forbidden response has a 4xx status code
func (o *PatchScriptForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch script forbidden response has a 5xx status code
func (o *PatchScriptForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script forbidden response a status code equal to that given
func (o *PatchScriptForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch script forbidden response
func (o *PatchScriptForbidden) Code() int {
	return 403
}

func (o *PatchScriptForbidden) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptForbidden  %+v", 403, o.Payload)
}

func (o *PatchScriptForbidden) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptForbidden  %+v", 403, o.Payload)
}

func (o *PatchScriptForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchScriptForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchScriptNotFound creates a PatchScriptNotFound with default headers values
func NewPatchScriptNotFound() *PatchScriptNotFound {
	return &PatchScriptNotFound{}
}

/*
PatchScriptNotFound describes a response with status code 404, with default header values.

Not found
*/
type PatchScriptNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch script not found response has a 2xx status code
func (o *PatchScriptNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch script not found response has a 3xx status code
func (o *PatchScriptNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script not found response has a 4xx status code
func (o *PatchScriptNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch script not found response has a 5xx status code
func (o *PatchScriptNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script not found response a status code equal to that given
func (o *PatchScriptNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the patch script not found response
func (o *PatchScriptNotFound) Code() int {
	return 404
}

func (o *PatchScriptNotFound) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptNotFound  %+v", 404, o.Payload)
}

func (o *PatchScriptNotFound) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptNotFound  %+v", 404, o.Payload)
}

func (o *PatchScriptNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchScriptNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchScriptTooManyRequests creates a PatchScriptTooManyRequests with default headers values
func NewPatchScriptTooManyRequests() *PatchScriptTooManyRequests {
	return &PatchScriptTooManyRequests{}
}

/*
PatchScriptTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type PatchScriptTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch script too many requests response has a 2xx status code
func (o *PatchScriptTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch script too many requests response has a 3xx status code
func (o *PatchScriptTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch script too many requests response has a 4xx status code
func (o *PatchScriptTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch script too many requests response has a 5xx status code
func (o *PatchScriptTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch script too many requests response a status code equal to that given
func (o *PatchScriptTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch script too many requests response
func (o *PatchScriptTooManyRequests) Code() int {
	return 429
}

func (o *PatchScriptTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchScriptTooManyRequests) String() string {
	return fmt.Sprintf("[PATCH /servers/{wid}/scripts/{script}][%d] patchScriptTooManyRequests  %+v", 429, o.Payload)
}

func (o *PatchScriptTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchScriptTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
