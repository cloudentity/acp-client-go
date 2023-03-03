// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// RejectCDRArrangementSystemReader is a Reader for the RejectCDRArrangementSystem structure.
type RejectCDRArrangementSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectCDRArrangementSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectCDRArrangementSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRejectCDRArrangementSystemBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRejectCDRArrangementSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectCDRArrangementSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectCDRArrangementSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectCDRArrangementSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectCDRArrangementSystemOK creates a RejectCDRArrangementSystemOK with default headers values
func NewRejectCDRArrangementSystemOK() *RejectCDRArrangementSystemOK {
	return &RejectCDRArrangementSystemOK{}
}

/*
RejectCDRArrangementSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectCDRArrangementSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject c d r arrangement system o k response has a 2xx status code
func (o *RejectCDRArrangementSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject c d r arrangement system o k response has a 3xx status code
func (o *RejectCDRArrangementSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system o k response has a 4xx status code
func (o *RejectCDRArrangementSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject c d r arrangement system o k response has a 5xx status code
func (o *RejectCDRArrangementSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system o k response a status code equal to that given
func (o *RejectCDRArrangementSystemOK) IsCode(code int) bool {
	return code == 200
}

func (o *RejectCDRArrangementSystemOK) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemOK  %+v", 200, o.Payload)
}

func (o *RejectCDRArrangementSystemOK) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemOK  %+v", 200, o.Payload)
}

func (o *RejectCDRArrangementSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectCDRArrangementSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectCDRArrangementSystemBadRequest creates a RejectCDRArrangementSystemBadRequest with default headers values
func NewRejectCDRArrangementSystemBadRequest() *RejectCDRArrangementSystemBadRequest {
	return &RejectCDRArrangementSystemBadRequest{}
}

/*
RejectCDRArrangementSystemBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type RejectCDRArrangementSystemBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject c d r arrangement system bad request response has a 2xx status code
func (o *RejectCDRArrangementSystemBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject c d r arrangement system bad request response has a 3xx status code
func (o *RejectCDRArrangementSystemBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system bad request response has a 4xx status code
func (o *RejectCDRArrangementSystemBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject c d r arrangement system bad request response has a 5xx status code
func (o *RejectCDRArrangementSystemBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system bad request response a status code equal to that given
func (o *RejectCDRArrangementSystemBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *RejectCDRArrangementSystemBadRequest) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemBadRequest  %+v", 400, o.Payload)
}

func (o *RejectCDRArrangementSystemBadRequest) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemBadRequest  %+v", 400, o.Payload)
}

func (o *RejectCDRArrangementSystemBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectCDRArrangementSystemBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectCDRArrangementSystemUnauthorized creates a RejectCDRArrangementSystemUnauthorized with default headers values
func NewRejectCDRArrangementSystemUnauthorized() *RejectCDRArrangementSystemUnauthorized {
	return &RejectCDRArrangementSystemUnauthorized{}
}

/*
RejectCDRArrangementSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RejectCDRArrangementSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject c d r arrangement system unauthorized response has a 2xx status code
func (o *RejectCDRArrangementSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject c d r arrangement system unauthorized response has a 3xx status code
func (o *RejectCDRArrangementSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system unauthorized response has a 4xx status code
func (o *RejectCDRArrangementSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject c d r arrangement system unauthorized response has a 5xx status code
func (o *RejectCDRArrangementSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system unauthorized response a status code equal to that given
func (o *RejectCDRArrangementSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *RejectCDRArrangementSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectCDRArrangementSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectCDRArrangementSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectCDRArrangementSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectCDRArrangementSystemForbidden creates a RejectCDRArrangementSystemForbidden with default headers values
func NewRejectCDRArrangementSystemForbidden() *RejectCDRArrangementSystemForbidden {
	return &RejectCDRArrangementSystemForbidden{}
}

/*
RejectCDRArrangementSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RejectCDRArrangementSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject c d r arrangement system forbidden response has a 2xx status code
func (o *RejectCDRArrangementSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject c d r arrangement system forbidden response has a 3xx status code
func (o *RejectCDRArrangementSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system forbidden response has a 4xx status code
func (o *RejectCDRArrangementSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject c d r arrangement system forbidden response has a 5xx status code
func (o *RejectCDRArrangementSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system forbidden response a status code equal to that given
func (o *RejectCDRArrangementSystemForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *RejectCDRArrangementSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectCDRArrangementSystemForbidden) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectCDRArrangementSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectCDRArrangementSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectCDRArrangementSystemNotFound creates a RejectCDRArrangementSystemNotFound with default headers values
func NewRejectCDRArrangementSystemNotFound() *RejectCDRArrangementSystemNotFound {
	return &RejectCDRArrangementSystemNotFound{}
}

/*
RejectCDRArrangementSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RejectCDRArrangementSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject c d r arrangement system not found response has a 2xx status code
func (o *RejectCDRArrangementSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject c d r arrangement system not found response has a 3xx status code
func (o *RejectCDRArrangementSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system not found response has a 4xx status code
func (o *RejectCDRArrangementSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject c d r arrangement system not found response has a 5xx status code
func (o *RejectCDRArrangementSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system not found response a status code equal to that given
func (o *RejectCDRArrangementSystemNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *RejectCDRArrangementSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectCDRArrangementSystemNotFound) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectCDRArrangementSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectCDRArrangementSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectCDRArrangementSystemTooManyRequests creates a RejectCDRArrangementSystemTooManyRequests with default headers values
func NewRejectCDRArrangementSystemTooManyRequests() *RejectCDRArrangementSystemTooManyRequests {
	return &RejectCDRArrangementSystemTooManyRequests{}
}

/*
RejectCDRArrangementSystemTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type RejectCDRArrangementSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject c d r arrangement system too many requests response has a 2xx status code
func (o *RejectCDRArrangementSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject c d r arrangement system too many requests response has a 3xx status code
func (o *RejectCDRArrangementSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject c d r arrangement system too many requests response has a 4xx status code
func (o *RejectCDRArrangementSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject c d r arrangement system too many requests response has a 5xx status code
func (o *RejectCDRArrangementSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject c d r arrangement system too many requests response a status code equal to that given
func (o *RejectCDRArrangementSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *RejectCDRArrangementSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectCDRArrangementSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/reject][%d] rejectCDRArrangementSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectCDRArrangementSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectCDRArrangementSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
