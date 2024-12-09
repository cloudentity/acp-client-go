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

// GetOrganizationIDPReader is a Reader for the GetOrganizationIDP structure.
type GetOrganizationIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOrganizationIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOrganizationIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetOrganizationIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetOrganizationIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetOrganizationIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetOrganizationIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/organization/{iid}] getOrganizationIDP", response, response.Code())
	}
}

// NewGetOrganizationIDPOK creates a GetOrganizationIDPOK with default headers values
func NewGetOrganizationIDPOK() *GetOrganizationIDPOK {
	return &GetOrganizationIDPOK{}
}

/*
GetOrganizationIDPOK describes a response with status code 200, with default header values.

OrganizationIDP
*/
type GetOrganizationIDPOK struct {
	Payload *models.OrganizationIDP
}

// IsSuccess returns true when this get organization Id p o k response has a 2xx status code
func (o *GetOrganizationIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get organization Id p o k response has a 3xx status code
func (o *GetOrganizationIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization Id p o k response has a 4xx status code
func (o *GetOrganizationIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get organization Id p o k response has a 5xx status code
func (o *GetOrganizationIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization Id p o k response a status code equal to that given
func (o *GetOrganizationIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get organization Id p o k response
func (o *GetOrganizationIDPOK) Code() int {
	return 200
}

func (o *GetOrganizationIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPOK  %+v", 200, o.Payload)
}

func (o *GetOrganizationIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPOK  %+v", 200, o.Payload)
}

func (o *GetOrganizationIDPOK) GetPayload() *models.OrganizationIDP {
	return o.Payload
}

func (o *GetOrganizationIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OrganizationIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationIDPUnauthorized creates a GetOrganizationIDPUnauthorized with default headers values
func NewGetOrganizationIDPUnauthorized() *GetOrganizationIDPUnauthorized {
	return &GetOrganizationIDPUnauthorized{}
}

/*
GetOrganizationIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetOrganizationIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization Id p unauthorized response has a 2xx status code
func (o *GetOrganizationIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization Id p unauthorized response has a 3xx status code
func (o *GetOrganizationIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization Id p unauthorized response has a 4xx status code
func (o *GetOrganizationIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization Id p unauthorized response has a 5xx status code
func (o *GetOrganizationIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization Id p unauthorized response a status code equal to that given
func (o *GetOrganizationIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get organization Id p unauthorized response
func (o *GetOrganizationIDPUnauthorized) Code() int {
	return 401
}

func (o *GetOrganizationIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOrganizationIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetOrganizationIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationIDPForbidden creates a GetOrganizationIDPForbidden with default headers values
func NewGetOrganizationIDPForbidden() *GetOrganizationIDPForbidden {
	return &GetOrganizationIDPForbidden{}
}

/*
GetOrganizationIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetOrganizationIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization Id p forbidden response has a 2xx status code
func (o *GetOrganizationIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization Id p forbidden response has a 3xx status code
func (o *GetOrganizationIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization Id p forbidden response has a 4xx status code
func (o *GetOrganizationIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization Id p forbidden response has a 5xx status code
func (o *GetOrganizationIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization Id p forbidden response a status code equal to that given
func (o *GetOrganizationIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get organization Id p forbidden response
func (o *GetOrganizationIDPForbidden) Code() int {
	return 403
}

func (o *GetOrganizationIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetOrganizationIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetOrganizationIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationIDPNotFound creates a GetOrganizationIDPNotFound with default headers values
func NewGetOrganizationIDPNotFound() *GetOrganizationIDPNotFound {
	return &GetOrganizationIDPNotFound{}
}

/*
GetOrganizationIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetOrganizationIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization Id p not found response has a 2xx status code
func (o *GetOrganizationIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization Id p not found response has a 3xx status code
func (o *GetOrganizationIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization Id p not found response has a 4xx status code
func (o *GetOrganizationIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization Id p not found response has a 5xx status code
func (o *GetOrganizationIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization Id p not found response a status code equal to that given
func (o *GetOrganizationIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get organization Id p not found response
func (o *GetOrganizationIDPNotFound) Code() int {
	return 404
}

func (o *GetOrganizationIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetOrganizationIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetOrganizationIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrganizationIDPTooManyRequests creates a GetOrganizationIDPTooManyRequests with default headers values
func NewGetOrganizationIDPTooManyRequests() *GetOrganizationIDPTooManyRequests {
	return &GetOrganizationIDPTooManyRequests{}
}

/*
GetOrganizationIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetOrganizationIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get organization Id p too many requests response has a 2xx status code
func (o *GetOrganizationIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get organization Id p too many requests response has a 3xx status code
func (o *GetOrganizationIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get organization Id p too many requests response has a 4xx status code
func (o *GetOrganizationIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get organization Id p too many requests response has a 5xx status code
func (o *GetOrganizationIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get organization Id p too many requests response a status code equal to that given
func (o *GetOrganizationIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get organization Id p too many requests response
func (o *GetOrganizationIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetOrganizationIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOrganizationIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/organization/{iid}][%d] getOrganizationIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetOrganizationIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrganizationIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
