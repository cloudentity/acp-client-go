// Code generated by go-swagger; DO NOT EDIT.

package roles

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

// GrantWorkspaceRoleReader is a Reader for the GrantWorkspaceRole structure.
type GrantWorkspaceRoleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GrantWorkspaceRoleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewGrantWorkspaceRoleNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGrantWorkspaceRoleUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGrantWorkspaceRoleForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGrantWorkspaceRoleNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGrantWorkspaceRoleUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGrantWorkspaceRoleTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /servers/{wid}/roles/grant] grantWorkspaceRole", response, response.Code())
	}
}

// NewGrantWorkspaceRoleNoContent creates a GrantWorkspaceRoleNoContent with default headers values
func NewGrantWorkspaceRoleNoContent() *GrantWorkspaceRoleNoContent {
	return &GrantWorkspaceRoleNoContent{}
}

/*
GrantWorkspaceRoleNoContent describes a response with status code 204, with default header values.

Role granted
*/
type GrantWorkspaceRoleNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this grant workspace role no content response has a 2xx status code
func (o *GrantWorkspaceRoleNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this grant workspace role no content response has a 3xx status code
func (o *GrantWorkspaceRoleNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role no content response has a 4xx status code
func (o *GrantWorkspaceRoleNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this grant workspace role no content response has a 5xx status code
func (o *GrantWorkspaceRoleNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role no content response a status code equal to that given
func (o *GrantWorkspaceRoleNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the grant workspace role no content response
func (o *GrantWorkspaceRoleNoContent) Code() int {
	return 204
}

func (o *GrantWorkspaceRoleNoContent) Error() string {
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleNoContent", 204)
}

func (o *GrantWorkspaceRoleNoContent) String() string {
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleNoContent", 204)
}

func (o *GrantWorkspaceRoleNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewGrantWorkspaceRoleUnauthorized creates a GrantWorkspaceRoleUnauthorized with default headers values
func NewGrantWorkspaceRoleUnauthorized() *GrantWorkspaceRoleUnauthorized {
	return &GrantWorkspaceRoleUnauthorized{}
}

/*
GrantWorkspaceRoleUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GrantWorkspaceRoleUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant workspace role unauthorized response has a 2xx status code
func (o *GrantWorkspaceRoleUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant workspace role unauthorized response has a 3xx status code
func (o *GrantWorkspaceRoleUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role unauthorized response has a 4xx status code
func (o *GrantWorkspaceRoleUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant workspace role unauthorized response has a 5xx status code
func (o *GrantWorkspaceRoleUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role unauthorized response a status code equal to that given
func (o *GrantWorkspaceRoleUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the grant workspace role unauthorized response
func (o *GrantWorkspaceRoleUnauthorized) Code() int {
	return 401
}

func (o *GrantWorkspaceRoleUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleUnauthorized %s", 401, payload)
}

func (o *GrantWorkspaceRoleUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleUnauthorized %s", 401, payload)
}

func (o *GrantWorkspaceRoleUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantWorkspaceRoleUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantWorkspaceRoleForbidden creates a GrantWorkspaceRoleForbidden with default headers values
func NewGrantWorkspaceRoleForbidden() *GrantWorkspaceRoleForbidden {
	return &GrantWorkspaceRoleForbidden{}
}

/*
GrantWorkspaceRoleForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GrantWorkspaceRoleForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant workspace role forbidden response has a 2xx status code
func (o *GrantWorkspaceRoleForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant workspace role forbidden response has a 3xx status code
func (o *GrantWorkspaceRoleForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role forbidden response has a 4xx status code
func (o *GrantWorkspaceRoleForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant workspace role forbidden response has a 5xx status code
func (o *GrantWorkspaceRoleForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role forbidden response a status code equal to that given
func (o *GrantWorkspaceRoleForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the grant workspace role forbidden response
func (o *GrantWorkspaceRoleForbidden) Code() int {
	return 403
}

func (o *GrantWorkspaceRoleForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleForbidden %s", 403, payload)
}

func (o *GrantWorkspaceRoleForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleForbidden %s", 403, payload)
}

func (o *GrantWorkspaceRoleForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantWorkspaceRoleForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantWorkspaceRoleNotFound creates a GrantWorkspaceRoleNotFound with default headers values
func NewGrantWorkspaceRoleNotFound() *GrantWorkspaceRoleNotFound {
	return &GrantWorkspaceRoleNotFound{}
}

/*
GrantWorkspaceRoleNotFound describes a response with status code 404, with default header values.

Not found
*/
type GrantWorkspaceRoleNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant workspace role not found response has a 2xx status code
func (o *GrantWorkspaceRoleNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant workspace role not found response has a 3xx status code
func (o *GrantWorkspaceRoleNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role not found response has a 4xx status code
func (o *GrantWorkspaceRoleNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant workspace role not found response has a 5xx status code
func (o *GrantWorkspaceRoleNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role not found response a status code equal to that given
func (o *GrantWorkspaceRoleNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the grant workspace role not found response
func (o *GrantWorkspaceRoleNotFound) Code() int {
	return 404
}

func (o *GrantWorkspaceRoleNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleNotFound %s", 404, payload)
}

func (o *GrantWorkspaceRoleNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleNotFound %s", 404, payload)
}

func (o *GrantWorkspaceRoleNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantWorkspaceRoleNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantWorkspaceRoleUnprocessableEntity creates a GrantWorkspaceRoleUnprocessableEntity with default headers values
func NewGrantWorkspaceRoleUnprocessableEntity() *GrantWorkspaceRoleUnprocessableEntity {
	return &GrantWorkspaceRoleUnprocessableEntity{}
}

/*
GrantWorkspaceRoleUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type GrantWorkspaceRoleUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant workspace role unprocessable entity response has a 2xx status code
func (o *GrantWorkspaceRoleUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant workspace role unprocessable entity response has a 3xx status code
func (o *GrantWorkspaceRoleUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role unprocessable entity response has a 4xx status code
func (o *GrantWorkspaceRoleUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant workspace role unprocessable entity response has a 5xx status code
func (o *GrantWorkspaceRoleUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role unprocessable entity response a status code equal to that given
func (o *GrantWorkspaceRoleUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the grant workspace role unprocessable entity response
func (o *GrantWorkspaceRoleUnprocessableEntity) Code() int {
	return 422
}

func (o *GrantWorkspaceRoleUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleUnprocessableEntity %s", 422, payload)
}

func (o *GrantWorkspaceRoleUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleUnprocessableEntity %s", 422, payload)
}

func (o *GrantWorkspaceRoleUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantWorkspaceRoleUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantWorkspaceRoleTooManyRequests creates a GrantWorkspaceRoleTooManyRequests with default headers values
func NewGrantWorkspaceRoleTooManyRequests() *GrantWorkspaceRoleTooManyRequests {
	return &GrantWorkspaceRoleTooManyRequests{}
}

/*
GrantWorkspaceRoleTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GrantWorkspaceRoleTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant workspace role too many requests response has a 2xx status code
func (o *GrantWorkspaceRoleTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant workspace role too many requests response has a 3xx status code
func (o *GrantWorkspaceRoleTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant workspace role too many requests response has a 4xx status code
func (o *GrantWorkspaceRoleTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant workspace role too many requests response has a 5xx status code
func (o *GrantWorkspaceRoleTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this grant workspace role too many requests response a status code equal to that given
func (o *GrantWorkspaceRoleTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the grant workspace role too many requests response
func (o *GrantWorkspaceRoleTooManyRequests) Code() int {
	return 429
}

func (o *GrantWorkspaceRoleTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleTooManyRequests %s", 429, payload)
}

func (o *GrantWorkspaceRoleTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /servers/{wid}/roles/grant][%d] grantWorkspaceRoleTooManyRequests %s", 429, payload)
}

func (o *GrantWorkspaceRoleTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantWorkspaceRoleTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
