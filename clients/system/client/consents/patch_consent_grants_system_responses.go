// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// PatchConsentGrantsSystemReader is a Reader for the PatchConsentGrantsSystem structure.
type PatchConsentGrantsSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchConsentGrantsSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPatchConsentGrantsSystemCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewPatchConsentGrantsSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewPatchConsentGrantsSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchConsentGrantsSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPatchConsentGrantsSystemConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewPatchConsentGrantsSystemUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchConsentGrantsSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PATCH /consents] patchConsentGrantsSystem", response, response.Code())
	}
}

// NewPatchConsentGrantsSystemCreated creates a PatchConsentGrantsSystemCreated with default headers values
func NewPatchConsentGrantsSystemCreated() *PatchConsentGrantsSystemCreated {
	return &PatchConsentGrantsSystemCreated{}
}

/*
PatchConsentGrantsSystemCreated describes a response with status code 201, with default header values.

Consent grant patch response
*/
type PatchConsentGrantsSystemCreated struct {
	Payload *models.ConsentGrantPatchResponse
}

// IsSuccess returns true when this patch consent grants system created response has a 2xx status code
func (o *PatchConsentGrantsSystemCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this patch consent grants system created response has a 3xx status code
func (o *PatchConsentGrantsSystemCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system created response has a 4xx status code
func (o *PatchConsentGrantsSystemCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this patch consent grants system created response has a 5xx status code
func (o *PatchConsentGrantsSystemCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system created response a status code equal to that given
func (o *PatchConsentGrantsSystemCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the patch consent grants system created response
func (o *PatchConsentGrantsSystemCreated) Code() int {
	return 201
}

func (o *PatchConsentGrantsSystemCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemCreated %s", 201, payload)
}

func (o *PatchConsentGrantsSystemCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemCreated %s", 201, payload)
}

func (o *PatchConsentGrantsSystemCreated) GetPayload() *models.ConsentGrantPatchResponse {
	return o.Payload
}

func (o *PatchConsentGrantsSystemCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentGrantPatchResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemUnauthorized creates a PatchConsentGrantsSystemUnauthorized with default headers values
func NewPatchConsentGrantsSystemUnauthorized() *PatchConsentGrantsSystemUnauthorized {
	return &PatchConsentGrantsSystemUnauthorized{}
}

/*
PatchConsentGrantsSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PatchConsentGrantsSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system unauthorized response has a 2xx status code
func (o *PatchConsentGrantsSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system unauthorized response has a 3xx status code
func (o *PatchConsentGrantsSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system unauthorized response has a 4xx status code
func (o *PatchConsentGrantsSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system unauthorized response has a 5xx status code
func (o *PatchConsentGrantsSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system unauthorized response a status code equal to that given
func (o *PatchConsentGrantsSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the patch consent grants system unauthorized response
func (o *PatchConsentGrantsSystemUnauthorized) Code() int {
	return 401
}

func (o *PatchConsentGrantsSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemUnauthorized %s", 401, payload)
}

func (o *PatchConsentGrantsSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemUnauthorized %s", 401, payload)
}

func (o *PatchConsentGrantsSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemForbidden creates a PatchConsentGrantsSystemForbidden with default headers values
func NewPatchConsentGrantsSystemForbidden() *PatchConsentGrantsSystemForbidden {
	return &PatchConsentGrantsSystemForbidden{}
}

/*
PatchConsentGrantsSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type PatchConsentGrantsSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system forbidden response has a 2xx status code
func (o *PatchConsentGrantsSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system forbidden response has a 3xx status code
func (o *PatchConsentGrantsSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system forbidden response has a 4xx status code
func (o *PatchConsentGrantsSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system forbidden response has a 5xx status code
func (o *PatchConsentGrantsSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system forbidden response a status code equal to that given
func (o *PatchConsentGrantsSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the patch consent grants system forbidden response
func (o *PatchConsentGrantsSystemForbidden) Code() int {
	return 403
}

func (o *PatchConsentGrantsSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemForbidden %s", 403, payload)
}

func (o *PatchConsentGrantsSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemForbidden %s", 403, payload)
}

func (o *PatchConsentGrantsSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemNotFound creates a PatchConsentGrantsSystemNotFound with default headers values
func NewPatchConsentGrantsSystemNotFound() *PatchConsentGrantsSystemNotFound {
	return &PatchConsentGrantsSystemNotFound{}
}

/*
PatchConsentGrantsSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type PatchConsentGrantsSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system not found response has a 2xx status code
func (o *PatchConsentGrantsSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system not found response has a 3xx status code
func (o *PatchConsentGrantsSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system not found response has a 4xx status code
func (o *PatchConsentGrantsSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system not found response has a 5xx status code
func (o *PatchConsentGrantsSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system not found response a status code equal to that given
func (o *PatchConsentGrantsSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the patch consent grants system not found response
func (o *PatchConsentGrantsSystemNotFound) Code() int {
	return 404
}

func (o *PatchConsentGrantsSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemNotFound %s", 404, payload)
}

func (o *PatchConsentGrantsSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemNotFound %s", 404, payload)
}

func (o *PatchConsentGrantsSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemConflict creates a PatchConsentGrantsSystemConflict with default headers values
func NewPatchConsentGrantsSystemConflict() *PatchConsentGrantsSystemConflict {
	return &PatchConsentGrantsSystemConflict{}
}

/*
PatchConsentGrantsSystemConflict describes a response with status code 409, with default header values.

Conflict
*/
type PatchConsentGrantsSystemConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system conflict response has a 2xx status code
func (o *PatchConsentGrantsSystemConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system conflict response has a 3xx status code
func (o *PatchConsentGrantsSystemConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system conflict response has a 4xx status code
func (o *PatchConsentGrantsSystemConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system conflict response has a 5xx status code
func (o *PatchConsentGrantsSystemConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system conflict response a status code equal to that given
func (o *PatchConsentGrantsSystemConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the patch consent grants system conflict response
func (o *PatchConsentGrantsSystemConflict) Code() int {
	return 409
}

func (o *PatchConsentGrantsSystemConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemConflict %s", 409, payload)
}

func (o *PatchConsentGrantsSystemConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemConflict %s", 409, payload)
}

func (o *PatchConsentGrantsSystemConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemUnprocessableEntity creates a PatchConsentGrantsSystemUnprocessableEntity with default headers values
func NewPatchConsentGrantsSystemUnprocessableEntity() *PatchConsentGrantsSystemUnprocessableEntity {
	return &PatchConsentGrantsSystemUnprocessableEntity{}
}

/*
PatchConsentGrantsSystemUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type PatchConsentGrantsSystemUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system unprocessable entity response has a 2xx status code
func (o *PatchConsentGrantsSystemUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system unprocessable entity response has a 3xx status code
func (o *PatchConsentGrantsSystemUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system unprocessable entity response has a 4xx status code
func (o *PatchConsentGrantsSystemUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system unprocessable entity response has a 5xx status code
func (o *PatchConsentGrantsSystemUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system unprocessable entity response a status code equal to that given
func (o *PatchConsentGrantsSystemUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the patch consent grants system unprocessable entity response
func (o *PatchConsentGrantsSystemUnprocessableEntity) Code() int {
	return 422
}

func (o *PatchConsentGrantsSystemUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemUnprocessableEntity %s", 422, payload)
}

func (o *PatchConsentGrantsSystemUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemUnprocessableEntity %s", 422, payload)
}

func (o *PatchConsentGrantsSystemUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchConsentGrantsSystemTooManyRequests creates a PatchConsentGrantsSystemTooManyRequests with default headers values
func NewPatchConsentGrantsSystemTooManyRequests() *PatchConsentGrantsSystemTooManyRequests {
	return &PatchConsentGrantsSystemTooManyRequests{}
}

/*
PatchConsentGrantsSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type PatchConsentGrantsSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this patch consent grants system too many requests response has a 2xx status code
func (o *PatchConsentGrantsSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this patch consent grants system too many requests response has a 3xx status code
func (o *PatchConsentGrantsSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this patch consent grants system too many requests response has a 4xx status code
func (o *PatchConsentGrantsSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this patch consent grants system too many requests response has a 5xx status code
func (o *PatchConsentGrantsSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this patch consent grants system too many requests response a status code equal to that given
func (o *PatchConsentGrantsSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the patch consent grants system too many requests response
func (o *PatchConsentGrantsSystemTooManyRequests) Code() int {
	return 429
}

func (o *PatchConsentGrantsSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemTooManyRequests %s", 429, payload)
}

func (o *PatchConsentGrantsSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PATCH /consents][%d] patchConsentGrantsSystemTooManyRequests %s", 429, payload)
}

func (o *PatchConsentGrantsSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *PatchConsentGrantsSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
