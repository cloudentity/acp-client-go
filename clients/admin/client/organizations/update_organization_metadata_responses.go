// Code generated by go-swagger; DO NOT EDIT.

package organizations

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

// UpdateOrganizationMetadataReader is a Reader for the UpdateOrganizationMetadata structure.
type UpdateOrganizationMetadataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateOrganizationMetadataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateOrganizationMetadataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewUpdateOrganizationMetadataUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewUpdateOrganizationMetadataForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateOrganizationMetadataNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewUpdateOrganizationMetadataTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /organizations/{wid}/metadata] updateOrganizationMetadata", response, response.Code())
	}
}

// NewUpdateOrganizationMetadataOK creates a UpdateOrganizationMetadataOK with default headers values
func NewUpdateOrganizationMetadataOK() *UpdateOrganizationMetadataOK {
	return &UpdateOrganizationMetadataOK{}
}

/*
UpdateOrganizationMetadataOK describes a response with status code 200, with default header values.

Organization metadata
*/
type UpdateOrganizationMetadataOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.OrganizationMetadata
}

// IsSuccess returns true when this update organization metadata o k response has a 2xx status code
func (o *UpdateOrganizationMetadataOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update organization metadata o k response has a 3xx status code
func (o *UpdateOrganizationMetadataOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update organization metadata o k response has a 4xx status code
func (o *UpdateOrganizationMetadataOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update organization metadata o k response has a 5xx status code
func (o *UpdateOrganizationMetadataOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update organization metadata o k response a status code equal to that given
func (o *UpdateOrganizationMetadataOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update organization metadata o k response
func (o *UpdateOrganizationMetadataOK) Code() int {
	return 200
}

func (o *UpdateOrganizationMetadataOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataOK %s", 200, payload)
}

func (o *UpdateOrganizationMetadataOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataOK %s", 200, payload)
}

func (o *UpdateOrganizationMetadataOK) GetPayload() *models.OrganizationMetadata {
	return o.Payload
}

func (o *UpdateOrganizationMetadataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.OrganizationMetadata)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateOrganizationMetadataUnauthorized creates a UpdateOrganizationMetadataUnauthorized with default headers values
func NewUpdateOrganizationMetadataUnauthorized() *UpdateOrganizationMetadataUnauthorized {
	return &UpdateOrganizationMetadataUnauthorized{}
}

/*
UpdateOrganizationMetadataUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type UpdateOrganizationMetadataUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this update organization metadata unauthorized response has a 2xx status code
func (o *UpdateOrganizationMetadataUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update organization metadata unauthorized response has a 3xx status code
func (o *UpdateOrganizationMetadataUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update organization metadata unauthorized response has a 4xx status code
func (o *UpdateOrganizationMetadataUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this update organization metadata unauthorized response has a 5xx status code
func (o *UpdateOrganizationMetadataUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this update organization metadata unauthorized response a status code equal to that given
func (o *UpdateOrganizationMetadataUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the update organization metadata unauthorized response
func (o *UpdateOrganizationMetadataUnauthorized) Code() int {
	return 401
}

func (o *UpdateOrganizationMetadataUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataUnauthorized %s", 401, payload)
}

func (o *UpdateOrganizationMetadataUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataUnauthorized %s", 401, payload)
}

func (o *UpdateOrganizationMetadataUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateOrganizationMetadataUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateOrganizationMetadataForbidden creates a UpdateOrganizationMetadataForbidden with default headers values
func NewUpdateOrganizationMetadataForbidden() *UpdateOrganizationMetadataForbidden {
	return &UpdateOrganizationMetadataForbidden{}
}

/*
UpdateOrganizationMetadataForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type UpdateOrganizationMetadataForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this update organization metadata forbidden response has a 2xx status code
func (o *UpdateOrganizationMetadataForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update organization metadata forbidden response has a 3xx status code
func (o *UpdateOrganizationMetadataForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update organization metadata forbidden response has a 4xx status code
func (o *UpdateOrganizationMetadataForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this update organization metadata forbidden response has a 5xx status code
func (o *UpdateOrganizationMetadataForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this update organization metadata forbidden response a status code equal to that given
func (o *UpdateOrganizationMetadataForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the update organization metadata forbidden response
func (o *UpdateOrganizationMetadataForbidden) Code() int {
	return 403
}

func (o *UpdateOrganizationMetadataForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataForbidden %s", 403, payload)
}

func (o *UpdateOrganizationMetadataForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataForbidden %s", 403, payload)
}

func (o *UpdateOrganizationMetadataForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateOrganizationMetadataForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateOrganizationMetadataNotFound creates a UpdateOrganizationMetadataNotFound with default headers values
func NewUpdateOrganizationMetadataNotFound() *UpdateOrganizationMetadataNotFound {
	return &UpdateOrganizationMetadataNotFound{}
}

/*
UpdateOrganizationMetadataNotFound describes a response with status code 404, with default header values.

Not found
*/
type UpdateOrganizationMetadataNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this update organization metadata not found response has a 2xx status code
func (o *UpdateOrganizationMetadataNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update organization metadata not found response has a 3xx status code
func (o *UpdateOrganizationMetadataNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update organization metadata not found response has a 4xx status code
func (o *UpdateOrganizationMetadataNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this update organization metadata not found response has a 5xx status code
func (o *UpdateOrganizationMetadataNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this update organization metadata not found response a status code equal to that given
func (o *UpdateOrganizationMetadataNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the update organization metadata not found response
func (o *UpdateOrganizationMetadataNotFound) Code() int {
	return 404
}

func (o *UpdateOrganizationMetadataNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataNotFound %s", 404, payload)
}

func (o *UpdateOrganizationMetadataNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataNotFound %s", 404, payload)
}

func (o *UpdateOrganizationMetadataNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateOrganizationMetadataNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateOrganizationMetadataTooManyRequests creates a UpdateOrganizationMetadataTooManyRequests with default headers values
func NewUpdateOrganizationMetadataTooManyRequests() *UpdateOrganizationMetadataTooManyRequests {
	return &UpdateOrganizationMetadataTooManyRequests{}
}

/*
UpdateOrganizationMetadataTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type UpdateOrganizationMetadataTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this update organization metadata too many requests response has a 2xx status code
func (o *UpdateOrganizationMetadataTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this update organization metadata too many requests response has a 3xx status code
func (o *UpdateOrganizationMetadataTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update organization metadata too many requests response has a 4xx status code
func (o *UpdateOrganizationMetadataTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this update organization metadata too many requests response has a 5xx status code
func (o *UpdateOrganizationMetadataTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this update organization metadata too many requests response a status code equal to that given
func (o *UpdateOrganizationMetadataTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the update organization metadata too many requests response
func (o *UpdateOrganizationMetadataTooManyRequests) Code() int {
	return 429
}

func (o *UpdateOrganizationMetadataTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataTooManyRequests %s", 429, payload)
}

func (o *UpdateOrganizationMetadataTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /organizations/{wid}/metadata][%d] updateOrganizationMetadataTooManyRequests %s", 429, payload)
}

func (o *UpdateOrganizationMetadataTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateOrganizationMetadataTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
