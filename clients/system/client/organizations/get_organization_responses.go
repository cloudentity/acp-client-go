// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// GetOrganizationReader is a Reader for the GetOrganization structure.
type GetOrganizationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOrganizationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOrganizationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetOrganizationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOrganizationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOrganizationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOrganizationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /organizations/{wid}] getOrganization", response, response.Code())
	}
}

// NewGetOrganizationOK creates a GetOrganizationOK with default headers values
func NewGetOrganizationOK() *GetOrganizationOK {
	return &GetOrganizationOK{}
}

/*
GetOrganizationOK describes a response with status code 200, with default header values.

Org
*/
type GetOrganizationOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.OrganizationResponse
}

// IsSuccess returns true when this get organization o k response has a 2xx status code
func (o *GetOrganizationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get organization o k response has a 3xx status code
func (o *GetOrganizationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization o k response has a 4xx status code
func (o *GetOrganizationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get organization o k response has a 5xx status code
func (o *GetOrganizationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization o k response a status code equal to that given
func (o *GetOrganizationOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get organization o k response
func (o *GetOrganizationOK) Code() int {
	return 200
}

func (o *GetOrganizationOK) Error() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationOK  %+v", 200, o.Payload)
}

func (o *GetOrganizationOK) String() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationOK  %+v", 200, o.Payload)
}

func (o *GetOrganizationOK) GetPayload() *models.OrganizationResponse {
	return o.Payload
}

func (o *GetOrganizationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.OrganizationResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationUnauthorized creates a GetOrganizationUnauthorized with default headers values
func NewGetOrganizationUnauthorized() *GetOrganizationUnauthorized {
	return &GetOrganizationUnauthorized{}
}

/*
GetOrganizationUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetOrganizationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization unauthorized response has a 2xx status code
func (o *GetOrganizationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization unauthorized response has a 3xx status code
func (o *GetOrganizationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization unauthorized response has a 4xx status code
func (o *GetOrganizationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization unauthorized response has a 5xx status code
func (o *GetOrganizationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization unauthorized response a status code equal to that given
func (o *GetOrganizationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get organization unauthorized response
func (o *GetOrganizationUnauthorized) Code() int {
	return 401
}

func (o *GetOrganizationUnauthorized) Error() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOrganizationUnauthorized) String() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOrganizationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationForbidden creates a GetOrganizationForbidden with default headers values
func NewGetOrganizationForbidden() *GetOrganizationForbidden {
	return &GetOrganizationForbidden{}
}

/*
GetOrganizationForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetOrganizationForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization forbidden response has a 2xx status code
func (o *GetOrganizationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization forbidden response has a 3xx status code
func (o *GetOrganizationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization forbidden response has a 4xx status code
func (o *GetOrganizationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization forbidden response has a 5xx status code
func (o *GetOrganizationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization forbidden response a status code equal to that given
func (o *GetOrganizationForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get organization forbidden response
func (o *GetOrganizationForbidden) Code() int {
	return 403
}

func (o *GetOrganizationForbidden) Error() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationForbidden  %+v", 403, o.Payload)
}

func (o *GetOrganizationForbidden) String() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationForbidden  %+v", 403, o.Payload)
}

func (o *GetOrganizationForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationNotFound creates a GetOrganizationNotFound with default headers values
func NewGetOrganizationNotFound() *GetOrganizationNotFound {
	return &GetOrganizationNotFound{}
}

/*
GetOrganizationNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetOrganizationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization not found response has a 2xx status code
func (o *GetOrganizationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization not found response has a 3xx status code
func (o *GetOrganizationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization not found response has a 4xx status code
func (o *GetOrganizationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization not found response has a 5xx status code
func (o *GetOrganizationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization not found response a status code equal to that given
func (o *GetOrganizationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get organization not found response
func (o *GetOrganizationNotFound) Code() int {
	return 404
}

func (o *GetOrganizationNotFound) Error() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationNotFound  %+v", 404, o.Payload)
}

func (o *GetOrganizationNotFound) String() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationNotFound  %+v", 404, o.Payload)
}

func (o *GetOrganizationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationTooManyRequests creates a GetOrganizationTooManyRequests with default headers values
func NewGetOrganizationTooManyRequests() *GetOrganizationTooManyRequests {
	return &GetOrganizationTooManyRequests{}
}

/*
GetOrganizationTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetOrganizationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization too many requests response has a 2xx status code
func (o *GetOrganizationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization too many requests response has a 3xx status code
func (o *GetOrganizationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization too many requests response has a 4xx status code
func (o *GetOrganizationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization too many requests response has a 5xx status code
func (o *GetOrganizationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization too many requests response a status code equal to that given
func (o *GetOrganizationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get organization too many requests response
func (o *GetOrganizationTooManyRequests) Code() int {
	return 429
}

func (o *GetOrganizationTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOrganizationTooManyRequests) String() string {
	return fmt.Sprintf("[GET /organizations/{wid}][%d] getOrganizationTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOrganizationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
