// Code generated by go-swagger; DO NOT EDIT.

package workspaces

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

// UpdateWorkspaceMetadataReader is a Reader for the UpdateWorkspaceMetadata structure.
type UpdateWorkspaceMetadataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateWorkspaceMetadataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateWorkspaceMetadataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUpdateWorkspaceMetadataUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateWorkspaceMetadataForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateWorkspaceMetadataNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateWorkspaceMetadataTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /workspaces/{wid}/metadata] updateWorkspaceMetadata", response, response.Code())
	}
}

// NewUpdateWorkspaceMetadataOK creates a UpdateWorkspaceMetadataOK with default headers values
func NewUpdateWorkspaceMetadataOK() *UpdateWorkspaceMetadataOK {
	return &UpdateWorkspaceMetadataOK{}
}

/*
UpdateWorkspaceMetadataOK describes a response with status code 200, with default header values.

Workspace metadata
*/
type UpdateWorkspaceMetadataOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.WorkspaceMetadata
}

// IsSuccess returns true when this update workspace metadata o k response has a 2xx status code
func (o *UpdateWorkspaceMetadataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update workspace metadata o k response has a 3xx status code
func (o *UpdateWorkspaceMetadataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update workspace metadata o k response has a 4xx status code
func (o *UpdateWorkspaceMetadataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update workspace metadata o k response has a 5xx status code
func (o *UpdateWorkspaceMetadataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update workspace metadata o k response a status code equal to that given
func (o *UpdateWorkspaceMetadataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update workspace metadata o k response
func (o *UpdateWorkspaceMetadataOK) Code() int {
	return 200
}

func (o *UpdateWorkspaceMetadataOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataOK %s", 200, payload)
}

func (o *UpdateWorkspaceMetadataOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataOK %s", 200, payload)
}

func (o *UpdateWorkspaceMetadataOK) GetPayload() *models.WorkspaceMetadata {
	return o.Payload
}

func (o *UpdateWorkspaceMetadataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.WorkspaceMetadata)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateWorkspaceMetadataUnauthorized creates a UpdateWorkspaceMetadataUnauthorized with default headers values
func NewUpdateWorkspaceMetadataUnauthorized() *UpdateWorkspaceMetadataUnauthorized {
	return &UpdateWorkspaceMetadataUnauthorized{}
}

/*
UpdateWorkspaceMetadataUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateWorkspaceMetadataUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update workspace metadata unauthorized response has a 2xx status code
func (o *UpdateWorkspaceMetadataUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update workspace metadata unauthorized response has a 3xx status code
func (o *UpdateWorkspaceMetadataUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update workspace metadata unauthorized response has a 4xx status code
func (o *UpdateWorkspaceMetadataUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update workspace metadata unauthorized response has a 5xx status code
func (o *UpdateWorkspaceMetadataUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update workspace metadata unauthorized response a status code equal to that given
func (o *UpdateWorkspaceMetadataUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update workspace metadata unauthorized response
func (o *UpdateWorkspaceMetadataUnauthorized) Code() int {
	return 401
}

func (o *UpdateWorkspaceMetadataUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataUnauthorized %s", 401, payload)
}

func (o *UpdateWorkspaceMetadataUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataUnauthorized %s", 401, payload)
}

func (o *UpdateWorkspaceMetadataUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateWorkspaceMetadataUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateWorkspaceMetadataForbidden creates a UpdateWorkspaceMetadataForbidden with default headers values
func NewUpdateWorkspaceMetadataForbidden() *UpdateWorkspaceMetadataForbidden {
	return &UpdateWorkspaceMetadataForbidden{}
}

/*
UpdateWorkspaceMetadataForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateWorkspaceMetadataForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update workspace metadata forbidden response has a 2xx status code
func (o *UpdateWorkspaceMetadataForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update workspace metadata forbidden response has a 3xx status code
func (o *UpdateWorkspaceMetadataForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update workspace metadata forbidden response has a 4xx status code
func (o *UpdateWorkspaceMetadataForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update workspace metadata forbidden response has a 5xx status code
func (o *UpdateWorkspaceMetadataForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update workspace metadata forbidden response a status code equal to that given
func (o *UpdateWorkspaceMetadataForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update workspace metadata forbidden response
func (o *UpdateWorkspaceMetadataForbidden) Code() int {
	return 403
}

func (o *UpdateWorkspaceMetadataForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataForbidden %s", 403, payload)
}

func (o *UpdateWorkspaceMetadataForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataForbidden %s", 403, payload)
}

func (o *UpdateWorkspaceMetadataForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateWorkspaceMetadataForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateWorkspaceMetadataNotFound creates a UpdateWorkspaceMetadataNotFound with default headers values
func NewUpdateWorkspaceMetadataNotFound() *UpdateWorkspaceMetadataNotFound {
	return &UpdateWorkspaceMetadataNotFound{}
}

/*
UpdateWorkspaceMetadataNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateWorkspaceMetadataNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update workspace metadata not found response has a 2xx status code
func (o *UpdateWorkspaceMetadataNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update workspace metadata not found response has a 3xx status code
func (o *UpdateWorkspaceMetadataNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update workspace metadata not found response has a 4xx status code
func (o *UpdateWorkspaceMetadataNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update workspace metadata not found response has a 5xx status code
func (o *UpdateWorkspaceMetadataNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update workspace metadata not found response a status code equal to that given
func (o *UpdateWorkspaceMetadataNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update workspace metadata not found response
func (o *UpdateWorkspaceMetadataNotFound) Code() int {
	return 404
}

func (o *UpdateWorkspaceMetadataNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataNotFound %s", 404, payload)
}

func (o *UpdateWorkspaceMetadataNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataNotFound %s", 404, payload)
}

func (o *UpdateWorkspaceMetadataNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateWorkspaceMetadataNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateWorkspaceMetadataTooManyRequests creates a UpdateWorkspaceMetadataTooManyRequests with default headers values
func NewUpdateWorkspaceMetadataTooManyRequests() *UpdateWorkspaceMetadataTooManyRequests {
	return &UpdateWorkspaceMetadataTooManyRequests{}
}

/*
UpdateWorkspaceMetadataTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateWorkspaceMetadataTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update workspace metadata too many requests response has a 2xx status code
func (o *UpdateWorkspaceMetadataTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update workspace metadata too many requests response has a 3xx status code
func (o *UpdateWorkspaceMetadataTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update workspace metadata too many requests response has a 4xx status code
func (o *UpdateWorkspaceMetadataTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update workspace metadata too many requests response has a 5xx status code
func (o *UpdateWorkspaceMetadataTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update workspace metadata too many requests response a status code equal to that given
func (o *UpdateWorkspaceMetadataTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update workspace metadata too many requests response
func (o *UpdateWorkspaceMetadataTooManyRequests) Code() int {
	return 429
}

func (o *UpdateWorkspaceMetadataTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataTooManyRequests %s", 429, payload)
}

func (o *UpdateWorkspaceMetadataTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /workspaces/{wid}/metadata][%d] updateWorkspaceMetadataTooManyRequests %s", 429, payload)
}

func (o *UpdateWorkspaceMetadataTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateWorkspaceMetadataTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
