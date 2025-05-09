// Code generated by go-swagger; DO NOT EDIT.

package root_configuration

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

// PatchSystemConfigRfc6902Reader is a Reader for the PatchSystemConfigRfc6902 structure.
type PatchSystemConfigRfc6902Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchSystemConfigRfc6902Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPatchSystemConfigRfc6902NoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchSystemConfigRfc6902BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchSystemConfigRfc6902Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchSystemConfigRfc6902Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchSystemConfigRfc6902NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchSystemConfigRfc6902UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchSystemConfigRfc6902TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /system/promote/config-rfc6902] patchSystemConfigRfc6902", response, response.Code())
	}
}

// NewPatchSystemConfigRfc6902NoContent creates a PatchSystemConfigRfc6902NoContent with default headers values
func NewPatchSystemConfigRfc6902NoContent() *PatchSystemConfigRfc6902NoContent {
	return &PatchSystemConfigRfc6902NoContent{}
}

/*
PatchSystemConfigRfc6902NoContent describes a response with status code 204, with default header values.

	patch applied
*/
type PatchSystemConfigRfc6902NoContent struct {
}

// IsSuccess returns true when this patch system config rfc6902 no content response has a 2xx status code
func (o *PatchSystemConfigRfc6902NoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch system config rfc6902 no content response has a 3xx status code
func (o *PatchSystemConfigRfc6902NoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 no content response has a 4xx status code
func (o *PatchSystemConfigRfc6902NoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch system config rfc6902 no content response has a 5xx status code
func (o *PatchSystemConfigRfc6902NoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 no content response a status code equal to that given
func (o *PatchSystemConfigRfc6902NoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the patch system config rfc6902 no content response
func (o *PatchSystemConfigRfc6902NoContent) Code() int {
	return 204
}

func (o *PatchSystemConfigRfc6902NoContent) Error() string {
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902NoContent", 204)
}

func (o *PatchSystemConfigRfc6902NoContent) String() string {
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902NoContent", 204)
}

func (o *PatchSystemConfigRfc6902NoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPatchSystemConfigRfc6902BadRequest creates a PatchSystemConfigRfc6902BadRequest with default headers values
func NewPatchSystemConfigRfc6902BadRequest() *PatchSystemConfigRfc6902BadRequest {
	return &PatchSystemConfigRfc6902BadRequest{}
}

/*
PatchSystemConfigRfc6902BadRequest describes a response with status code 400, with default header values.

Bad request
*/
type PatchSystemConfigRfc6902BadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 bad request response has a 2xx status code
func (o *PatchSystemConfigRfc6902BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 bad request response has a 3xx status code
func (o *PatchSystemConfigRfc6902BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 bad request response has a 4xx status code
func (o *PatchSystemConfigRfc6902BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 bad request response has a 5xx status code
func (o *PatchSystemConfigRfc6902BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 bad request response a status code equal to that given
func (o *PatchSystemConfigRfc6902BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the patch system config rfc6902 bad request response
func (o *PatchSystemConfigRfc6902BadRequest) Code() int {
	return 400
}

func (o *PatchSystemConfigRfc6902BadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902BadRequest %s", 400, payload)
}

func (o *PatchSystemConfigRfc6902BadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902BadRequest %s", 400, payload)
}

func (o *PatchSystemConfigRfc6902BadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchSystemConfigRfc6902Unauthorized creates a PatchSystemConfigRfc6902Unauthorized with default headers values
func NewPatchSystemConfigRfc6902Unauthorized() *PatchSystemConfigRfc6902Unauthorized {
	return &PatchSystemConfigRfc6902Unauthorized{}
}

/*
PatchSystemConfigRfc6902Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PatchSystemConfigRfc6902Unauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 unauthorized response has a 2xx status code
func (o *PatchSystemConfigRfc6902Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 unauthorized response has a 3xx status code
func (o *PatchSystemConfigRfc6902Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 unauthorized response has a 4xx status code
func (o *PatchSystemConfigRfc6902Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 unauthorized response has a 5xx status code
func (o *PatchSystemConfigRfc6902Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 unauthorized response a status code equal to that given
func (o *PatchSystemConfigRfc6902Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the patch system config rfc6902 unauthorized response
func (o *PatchSystemConfigRfc6902Unauthorized) Code() int {
	return 401
}

func (o *PatchSystemConfigRfc6902Unauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902Unauthorized %s", 401, payload)
}

func (o *PatchSystemConfigRfc6902Unauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902Unauthorized %s", 401, payload)
}

func (o *PatchSystemConfigRfc6902Unauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchSystemConfigRfc6902Forbidden creates a PatchSystemConfigRfc6902Forbidden with default headers values
func NewPatchSystemConfigRfc6902Forbidden() *PatchSystemConfigRfc6902Forbidden {
	return &PatchSystemConfigRfc6902Forbidden{}
}

/*
PatchSystemConfigRfc6902Forbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PatchSystemConfigRfc6902Forbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 forbidden response has a 2xx status code
func (o *PatchSystemConfigRfc6902Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 forbidden response has a 3xx status code
func (o *PatchSystemConfigRfc6902Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 forbidden response has a 4xx status code
func (o *PatchSystemConfigRfc6902Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 forbidden response has a 5xx status code
func (o *PatchSystemConfigRfc6902Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 forbidden response a status code equal to that given
func (o *PatchSystemConfigRfc6902Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch system config rfc6902 forbidden response
func (o *PatchSystemConfigRfc6902Forbidden) Code() int {
	return 403
}

func (o *PatchSystemConfigRfc6902Forbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902Forbidden %s", 403, payload)
}

func (o *PatchSystemConfigRfc6902Forbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902Forbidden %s", 403, payload)
}

func (o *PatchSystemConfigRfc6902Forbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchSystemConfigRfc6902NotFound creates a PatchSystemConfigRfc6902NotFound with default headers values
func NewPatchSystemConfigRfc6902NotFound() *PatchSystemConfigRfc6902NotFound {
	return &PatchSystemConfigRfc6902NotFound{}
}

/*
PatchSystemConfigRfc6902NotFound describes a response with status code 404, with default header values.

Not found
*/
type PatchSystemConfigRfc6902NotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 not found response has a 2xx status code
func (o *PatchSystemConfigRfc6902NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 not found response has a 3xx status code
func (o *PatchSystemConfigRfc6902NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 not found response has a 4xx status code
func (o *PatchSystemConfigRfc6902NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 not found response has a 5xx status code
func (o *PatchSystemConfigRfc6902NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 not found response a status code equal to that given
func (o *PatchSystemConfigRfc6902NotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the patch system config rfc6902 not found response
func (o *PatchSystemConfigRfc6902NotFound) Code() int {
	return 404
}

func (o *PatchSystemConfigRfc6902NotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902NotFound %s", 404, payload)
}

func (o *PatchSystemConfigRfc6902NotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902NotFound %s", 404, payload)
}

func (o *PatchSystemConfigRfc6902NotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchSystemConfigRfc6902UnprocessableEntity creates a PatchSystemConfigRfc6902UnprocessableEntity with default headers values
func NewPatchSystemConfigRfc6902UnprocessableEntity() *PatchSystemConfigRfc6902UnprocessableEntity {
	return &PatchSystemConfigRfc6902UnprocessableEntity{}
}

/*
PatchSystemConfigRfc6902UnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type PatchSystemConfigRfc6902UnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 unprocessable entity response has a 2xx status code
func (o *PatchSystemConfigRfc6902UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 unprocessable entity response has a 3xx status code
func (o *PatchSystemConfigRfc6902UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 unprocessable entity response has a 4xx status code
func (o *PatchSystemConfigRfc6902UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 unprocessable entity response has a 5xx status code
func (o *PatchSystemConfigRfc6902UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 unprocessable entity response a status code equal to that given
func (o *PatchSystemConfigRfc6902UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the patch system config rfc6902 unprocessable entity response
func (o *PatchSystemConfigRfc6902UnprocessableEntity) Code() int {
	return 422
}

func (o *PatchSystemConfigRfc6902UnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902UnprocessableEntity %s", 422, payload)
}

func (o *PatchSystemConfigRfc6902UnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902UnprocessableEntity %s", 422, payload)
}

func (o *PatchSystemConfigRfc6902UnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchSystemConfigRfc6902TooManyRequests creates a PatchSystemConfigRfc6902TooManyRequests with default headers values
func NewPatchSystemConfigRfc6902TooManyRequests() *PatchSystemConfigRfc6902TooManyRequests {
	return &PatchSystemConfigRfc6902TooManyRequests{}
}

/*
PatchSystemConfigRfc6902TooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type PatchSystemConfigRfc6902TooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch system config rfc6902 too many requests response has a 2xx status code
func (o *PatchSystemConfigRfc6902TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch system config rfc6902 too many requests response has a 3xx status code
func (o *PatchSystemConfigRfc6902TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch system config rfc6902 too many requests response has a 4xx status code
func (o *PatchSystemConfigRfc6902TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch system config rfc6902 too many requests response has a 5xx status code
func (o *PatchSystemConfigRfc6902TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch system config rfc6902 too many requests response a status code equal to that given
func (o *PatchSystemConfigRfc6902TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch system config rfc6902 too many requests response
func (o *PatchSystemConfigRfc6902TooManyRequests) Code() int {
	return 429
}

func (o *PatchSystemConfigRfc6902TooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902TooManyRequests %s", 429, payload)
}

func (o *PatchSystemConfigRfc6902TooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /system/promote/config-rfc6902][%d] patchSystemConfigRfc6902TooManyRequests %s", 429, payload)
}

func (o *PatchSystemConfigRfc6902TooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchSystemConfigRfc6902TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
