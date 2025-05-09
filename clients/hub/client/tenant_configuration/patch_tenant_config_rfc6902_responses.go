// Code generated by go-swagger; DO NOT EDIT.

package tenant_configuration

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/hub/models"
)

// PatchTenantConfigRfc6902Reader is a Reader for the PatchTenantConfigRfc6902 structure.
type PatchTenantConfigRfc6902Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchTenantConfigRfc6902Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPatchTenantConfigRfc6902NoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchTenantConfigRfc6902BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchTenantConfigRfc6902Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchTenantConfigRfc6902Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchTenantConfigRfc6902NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchTenantConfigRfc6902UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchTenantConfigRfc6902TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /{tid}/promote/config-rfc6902] patchTenantConfigRfc6902", response, response.Code())
	}
}

// NewPatchTenantConfigRfc6902NoContent creates a PatchTenantConfigRfc6902NoContent with default headers values
func NewPatchTenantConfigRfc6902NoContent() *PatchTenantConfigRfc6902NoContent {
	return &PatchTenantConfigRfc6902NoContent{}
}

/*
PatchTenantConfigRfc6902NoContent describes a response with status code 204, with default header values.

	patch applied
*/
type PatchTenantConfigRfc6902NoContent struct {
}

// IsSuccess returns true when this patch tenant config rfc6902 no content response has a 2xx status code
func (o *PatchTenantConfigRfc6902NoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch tenant config rfc6902 no content response has a 3xx status code
func (o *PatchTenantConfigRfc6902NoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 no content response has a 4xx status code
func (o *PatchTenantConfigRfc6902NoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch tenant config rfc6902 no content response has a 5xx status code
func (o *PatchTenantConfigRfc6902NoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 no content response a status code equal to that given
func (o *PatchTenantConfigRfc6902NoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the patch tenant config rfc6902 no content response
func (o *PatchTenantConfigRfc6902NoContent) Code() int {
	return 204
}

func (o *PatchTenantConfigRfc6902NoContent) Error() string {
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902NoContent", 204)
}

func (o *PatchTenantConfigRfc6902NoContent) String() string {
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902NoContent", 204)
}

func (o *PatchTenantConfigRfc6902NoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPatchTenantConfigRfc6902BadRequest creates a PatchTenantConfigRfc6902BadRequest with default headers values
func NewPatchTenantConfigRfc6902BadRequest() *PatchTenantConfigRfc6902BadRequest {
	return &PatchTenantConfigRfc6902BadRequest{}
}

/*
PatchTenantConfigRfc6902BadRequest describes a response with status code 400, with default header values.

Bad request
*/
type PatchTenantConfigRfc6902BadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 bad request response has a 2xx status code
func (o *PatchTenantConfigRfc6902BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 bad request response has a 3xx status code
func (o *PatchTenantConfigRfc6902BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 bad request response has a 4xx status code
func (o *PatchTenantConfigRfc6902BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 bad request response has a 5xx status code
func (o *PatchTenantConfigRfc6902BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 bad request response a status code equal to that given
func (o *PatchTenantConfigRfc6902BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the patch tenant config rfc6902 bad request response
func (o *PatchTenantConfigRfc6902BadRequest) Code() int {
	return 400
}

func (o *PatchTenantConfigRfc6902BadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902BadRequest %s", 400, payload)
}

func (o *PatchTenantConfigRfc6902BadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902BadRequest %s", 400, payload)
}

func (o *PatchTenantConfigRfc6902BadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchTenantConfigRfc6902Unauthorized creates a PatchTenantConfigRfc6902Unauthorized with default headers values
func NewPatchTenantConfigRfc6902Unauthorized() *PatchTenantConfigRfc6902Unauthorized {
	return &PatchTenantConfigRfc6902Unauthorized{}
}

/*
PatchTenantConfigRfc6902Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PatchTenantConfigRfc6902Unauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 unauthorized response has a 2xx status code
func (o *PatchTenantConfigRfc6902Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 unauthorized response has a 3xx status code
func (o *PatchTenantConfigRfc6902Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 unauthorized response has a 4xx status code
func (o *PatchTenantConfigRfc6902Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 unauthorized response has a 5xx status code
func (o *PatchTenantConfigRfc6902Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 unauthorized response a status code equal to that given
func (o *PatchTenantConfigRfc6902Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the patch tenant config rfc6902 unauthorized response
func (o *PatchTenantConfigRfc6902Unauthorized) Code() int {
	return 401
}

func (o *PatchTenantConfigRfc6902Unauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902Unauthorized %s", 401, payload)
}

func (o *PatchTenantConfigRfc6902Unauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902Unauthorized %s", 401, payload)
}

func (o *PatchTenantConfigRfc6902Unauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchTenantConfigRfc6902Forbidden creates a PatchTenantConfigRfc6902Forbidden with default headers values
func NewPatchTenantConfigRfc6902Forbidden() *PatchTenantConfigRfc6902Forbidden {
	return &PatchTenantConfigRfc6902Forbidden{}
}

/*
PatchTenantConfigRfc6902Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PatchTenantConfigRfc6902Forbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 forbidden response has a 2xx status code
func (o *PatchTenantConfigRfc6902Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 forbidden response has a 3xx status code
func (o *PatchTenantConfigRfc6902Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 forbidden response has a 4xx status code
func (o *PatchTenantConfigRfc6902Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 forbidden response has a 5xx status code
func (o *PatchTenantConfigRfc6902Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 forbidden response a status code equal to that given
func (o *PatchTenantConfigRfc6902Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch tenant config rfc6902 forbidden response
func (o *PatchTenantConfigRfc6902Forbidden) Code() int {
	return 403
}

func (o *PatchTenantConfigRfc6902Forbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902Forbidden %s", 403, payload)
}

func (o *PatchTenantConfigRfc6902Forbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902Forbidden %s", 403, payload)
}

func (o *PatchTenantConfigRfc6902Forbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchTenantConfigRfc6902NotFound creates a PatchTenantConfigRfc6902NotFound with default headers values
func NewPatchTenantConfigRfc6902NotFound() *PatchTenantConfigRfc6902NotFound {
	return &PatchTenantConfigRfc6902NotFound{}
}

/*
PatchTenantConfigRfc6902NotFound describes a response with status code 404, with default header values.

Not found
*/
type PatchTenantConfigRfc6902NotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 not found response has a 2xx status code
func (o *PatchTenantConfigRfc6902NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 not found response has a 3xx status code
func (o *PatchTenantConfigRfc6902NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 not found response has a 4xx status code
func (o *PatchTenantConfigRfc6902NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 not found response has a 5xx status code
func (o *PatchTenantConfigRfc6902NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 not found response a status code equal to that given
func (o *PatchTenantConfigRfc6902NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the patch tenant config rfc6902 not found response
func (o *PatchTenantConfigRfc6902NotFound) Code() int {
	return 404
}

func (o *PatchTenantConfigRfc6902NotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902NotFound %s", 404, payload)
}

func (o *PatchTenantConfigRfc6902NotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902NotFound %s", 404, payload)
}

func (o *PatchTenantConfigRfc6902NotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchTenantConfigRfc6902UnprocessableEntity creates a PatchTenantConfigRfc6902UnprocessableEntity with default headers values
func NewPatchTenantConfigRfc6902UnprocessableEntity() *PatchTenantConfigRfc6902UnprocessableEntity {
	return &PatchTenantConfigRfc6902UnprocessableEntity{}
}

/*
PatchTenantConfigRfc6902UnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type PatchTenantConfigRfc6902UnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 unprocessable entity response has a 2xx status code
func (o *PatchTenantConfigRfc6902UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 unprocessable entity response has a 3xx status code
func (o *PatchTenantConfigRfc6902UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 unprocessable entity response has a 4xx status code
func (o *PatchTenantConfigRfc6902UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 unprocessable entity response has a 5xx status code
func (o *PatchTenantConfigRfc6902UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 unprocessable entity response a status code equal to that given
func (o *PatchTenantConfigRfc6902UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the patch tenant config rfc6902 unprocessable entity response
func (o *PatchTenantConfigRfc6902UnprocessableEntity) Code() int {
	return 422
}

func (o *PatchTenantConfigRfc6902UnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902UnprocessableEntity %s", 422, payload)
}

func (o *PatchTenantConfigRfc6902UnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902UnprocessableEntity %s", 422, payload)
}

func (o *PatchTenantConfigRfc6902UnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchTenantConfigRfc6902TooManyRequests creates a PatchTenantConfigRfc6902TooManyRequests with default headers values
func NewPatchTenantConfigRfc6902TooManyRequests() *PatchTenantConfigRfc6902TooManyRequests {
	return &PatchTenantConfigRfc6902TooManyRequests{}
}

/*
PatchTenantConfigRfc6902TooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type PatchTenantConfigRfc6902TooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch tenant config rfc6902 too many requests response has a 2xx status code
func (o *PatchTenantConfigRfc6902TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch tenant config rfc6902 too many requests response has a 3xx status code
func (o *PatchTenantConfigRfc6902TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch tenant config rfc6902 too many requests response has a 4xx status code
func (o *PatchTenantConfigRfc6902TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch tenant config rfc6902 too many requests response has a 5xx status code
func (o *PatchTenantConfigRfc6902TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch tenant config rfc6902 too many requests response a status code equal to that given
func (o *PatchTenantConfigRfc6902TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch tenant config rfc6902 too many requests response
func (o *PatchTenantConfigRfc6902TooManyRequests) Code() int {
	return 429
}

func (o *PatchTenantConfigRfc6902TooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902TooManyRequests %s", 429, payload)
}

func (o *PatchTenantConfigRfc6902TooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /{tid}/promote/config-rfc6902][%d] patchTenantConfigRfc6902TooManyRequests %s", 429, payload)
}

func (o *PatchTenantConfigRfc6902TooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchTenantConfigRfc6902TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
