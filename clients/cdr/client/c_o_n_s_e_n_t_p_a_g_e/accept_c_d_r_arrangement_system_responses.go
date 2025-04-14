// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/cdr/models"
)

// AcceptCDRArrangementSystemReader is a Reader for the AcceptCDRArrangementSystem structure.
type AcceptCDRArrangementSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptCDRArrangementSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptCDRArrangementSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewAcceptCDRArrangementSystemBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewAcceptCDRArrangementSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptCDRArrangementSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptCDRArrangementSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAcceptCDRArrangementSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /cdr/cdr-arrangement/{login}/accept] acceptCDRArrangementSystem", response, response.Code())
	}
}

// NewAcceptCDRArrangementSystemOK creates a AcceptCDRArrangementSystemOK with default headers values
func NewAcceptCDRArrangementSystemOK() *AcceptCDRArrangementSystemOK {
	return &AcceptCDRArrangementSystemOK{}
}

/*
AcceptCDRArrangementSystemOK describes a response with status code 200, with default header values.

Consent Accepted
*/
type AcceptCDRArrangementSystemOK struct {
	Payload *models.ConsentAccepted
}

// IsSuccess returns true when this accept c d r arrangement system o k response has a 2xx status code
func (o *AcceptCDRArrangementSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accept c d r arrangement system o k response has a 3xx status code
func (o *AcceptCDRArrangementSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system o k response has a 4xx status code
func (o *AcceptCDRArrangementSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accept c d r arrangement system o k response has a 5xx status code
func (o *AcceptCDRArrangementSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system o k response a status code equal to that given
func (o *AcceptCDRArrangementSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accept c d r arrangement system o k response
func (o *AcceptCDRArrangementSystemOK) Code() int {
	return 200
}

func (o *AcceptCDRArrangementSystemOK) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemOK  %+v", 200, o.Payload)
}

func (o *AcceptCDRArrangementSystemOK) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemOK  %+v", 200, o.Payload)
}

func (o *AcceptCDRArrangementSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptCDRArrangementSystemBadRequest creates a AcceptCDRArrangementSystemBadRequest with default headers values
func NewAcceptCDRArrangementSystemBadRequest() *AcceptCDRArrangementSystemBadRequest {
	return &AcceptCDRArrangementSystemBadRequest{}
}

/*
AcceptCDRArrangementSystemBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type AcceptCDRArrangementSystemBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept c d r arrangement system bad request response has a 2xx status code
func (o *AcceptCDRArrangementSystemBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept c d r arrangement system bad request response has a 3xx status code
func (o *AcceptCDRArrangementSystemBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system bad request response has a 4xx status code
func (o *AcceptCDRArrangementSystemBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept c d r arrangement system bad request response has a 5xx status code
func (o *AcceptCDRArrangementSystemBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system bad request response a status code equal to that given
func (o *AcceptCDRArrangementSystemBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the accept c d r arrangement system bad request response
func (o *AcceptCDRArrangementSystemBadRequest) Code() int {
	return 400
}

func (o *AcceptCDRArrangementSystemBadRequest) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemBadRequest  %+v", 400, o.Payload)
}

func (o *AcceptCDRArrangementSystemBadRequest) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemBadRequest  %+v", 400, o.Payload)
}

func (o *AcceptCDRArrangementSystemBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptCDRArrangementSystemUnauthorized creates a AcceptCDRArrangementSystemUnauthorized with default headers values
func NewAcceptCDRArrangementSystemUnauthorized() *AcceptCDRArrangementSystemUnauthorized {
	return &AcceptCDRArrangementSystemUnauthorized{}
}

/*
AcceptCDRArrangementSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AcceptCDRArrangementSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept c d r arrangement system unauthorized response has a 2xx status code
func (o *AcceptCDRArrangementSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept c d r arrangement system unauthorized response has a 3xx status code
func (o *AcceptCDRArrangementSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system unauthorized response has a 4xx status code
func (o *AcceptCDRArrangementSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept c d r arrangement system unauthorized response has a 5xx status code
func (o *AcceptCDRArrangementSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system unauthorized response a status code equal to that given
func (o *AcceptCDRArrangementSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the accept c d r arrangement system unauthorized response
func (o *AcceptCDRArrangementSystemUnauthorized) Code() int {
	return 401
}

func (o *AcceptCDRArrangementSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *AcceptCDRArrangementSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *AcceptCDRArrangementSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptCDRArrangementSystemForbidden creates a AcceptCDRArrangementSystemForbidden with default headers values
func NewAcceptCDRArrangementSystemForbidden() *AcceptCDRArrangementSystemForbidden {
	return &AcceptCDRArrangementSystemForbidden{}
}

/*
AcceptCDRArrangementSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AcceptCDRArrangementSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept c d r arrangement system forbidden response has a 2xx status code
func (o *AcceptCDRArrangementSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept c d r arrangement system forbidden response has a 3xx status code
func (o *AcceptCDRArrangementSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system forbidden response has a 4xx status code
func (o *AcceptCDRArrangementSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept c d r arrangement system forbidden response has a 5xx status code
func (o *AcceptCDRArrangementSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system forbidden response a status code equal to that given
func (o *AcceptCDRArrangementSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the accept c d r arrangement system forbidden response
func (o *AcceptCDRArrangementSystemForbidden) Code() int {
	return 403
}

func (o *AcceptCDRArrangementSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemForbidden  %+v", 403, o.Payload)
}

func (o *AcceptCDRArrangementSystemForbidden) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemForbidden  %+v", 403, o.Payload)
}

func (o *AcceptCDRArrangementSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptCDRArrangementSystemNotFound creates a AcceptCDRArrangementSystemNotFound with default headers values
func NewAcceptCDRArrangementSystemNotFound() *AcceptCDRArrangementSystemNotFound {
	return &AcceptCDRArrangementSystemNotFound{}
}

/*
AcceptCDRArrangementSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type AcceptCDRArrangementSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept c d r arrangement system not found response has a 2xx status code
func (o *AcceptCDRArrangementSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept c d r arrangement system not found response has a 3xx status code
func (o *AcceptCDRArrangementSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system not found response has a 4xx status code
func (o *AcceptCDRArrangementSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept c d r arrangement system not found response has a 5xx status code
func (o *AcceptCDRArrangementSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system not found response a status code equal to that given
func (o *AcceptCDRArrangementSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the accept c d r arrangement system not found response
func (o *AcceptCDRArrangementSystemNotFound) Code() int {
	return 404
}

func (o *AcceptCDRArrangementSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemNotFound  %+v", 404, o.Payload)
}

func (o *AcceptCDRArrangementSystemNotFound) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemNotFound  %+v", 404, o.Payload)
}

func (o *AcceptCDRArrangementSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptCDRArrangementSystemTooManyRequests creates a AcceptCDRArrangementSystemTooManyRequests with default headers values
func NewAcceptCDRArrangementSystemTooManyRequests() *AcceptCDRArrangementSystemTooManyRequests {
	return &AcceptCDRArrangementSystemTooManyRequests{}
}

/*
AcceptCDRArrangementSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type AcceptCDRArrangementSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept c d r arrangement system too many requests response has a 2xx status code
func (o *AcceptCDRArrangementSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept c d r arrangement system too many requests response has a 3xx status code
func (o *AcceptCDRArrangementSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept c d r arrangement system too many requests response has a 4xx status code
func (o *AcceptCDRArrangementSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept c d r arrangement system too many requests response has a 5xx status code
func (o *AcceptCDRArrangementSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this accept c d r arrangement system too many requests response a status code equal to that given
func (o *AcceptCDRArrangementSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the accept c d r arrangement system too many requests response
func (o *AcceptCDRArrangementSystemTooManyRequests) Code() int {
	return 429
}

func (o *AcceptCDRArrangementSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *AcceptCDRArrangementSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /cdr/cdr-arrangement/{login}/accept][%d] acceptCDRArrangementSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *AcceptCDRArrangementSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptCDRArrangementSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
