// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// RejectFDXConsentSystemReader is a Reader for the RejectFDXConsentSystem structure.
type RejectFDXConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectFDXConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectFDXConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectFDXConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectFDXConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectFDXConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectFDXConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectFDXConsentSystemOK creates a RejectFDXConsentSystemOK with default headers values
func NewRejectFDXConsentSystemOK() *RejectFDXConsentSystemOK {
	return &RejectFDXConsentSystemOK{}
}

/*
RejectFDXConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectFDXConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject f d x consent system o k response has a 2xx status code
func (o *RejectFDXConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject f d x consent system o k response has a 3xx status code
func (o *RejectFDXConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject f d x consent system o k response has a 4xx status code
func (o *RejectFDXConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject f d x consent system o k response has a 5xx status code
func (o *RejectFDXConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject f d x consent system o k response a status code equal to that given
func (o *RejectFDXConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject f d x consent system o k response
func (o *RejectFDXConsentSystemOK) Code() int {
	return 200
}

func (o *RejectFDXConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectFDXConsentSystemOK) String() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectFDXConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectFDXConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFDXConsentSystemUnauthorized creates a RejectFDXConsentSystemUnauthorized with default headers values
func NewRejectFDXConsentSystemUnauthorized() *RejectFDXConsentSystemUnauthorized {
	return &RejectFDXConsentSystemUnauthorized{}
}

/*
RejectFDXConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectFDXConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject f d x consent system unauthorized response has a 2xx status code
func (o *RejectFDXConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject f d x consent system unauthorized response has a 3xx status code
func (o *RejectFDXConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject f d x consent system unauthorized response has a 4xx status code
func (o *RejectFDXConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject f d x consent system unauthorized response has a 5xx status code
func (o *RejectFDXConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject f d x consent system unauthorized response a status code equal to that given
func (o *RejectFDXConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject f d x consent system unauthorized response
func (o *RejectFDXConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectFDXConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectFDXConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectFDXConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFDXConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFDXConsentSystemForbidden creates a RejectFDXConsentSystemForbidden with default headers values
func NewRejectFDXConsentSystemForbidden() *RejectFDXConsentSystemForbidden {
	return &RejectFDXConsentSystemForbidden{}
}

/*
RejectFDXConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectFDXConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject f d x consent system forbidden response has a 2xx status code
func (o *RejectFDXConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject f d x consent system forbidden response has a 3xx status code
func (o *RejectFDXConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject f d x consent system forbidden response has a 4xx status code
func (o *RejectFDXConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject f d x consent system forbidden response has a 5xx status code
func (o *RejectFDXConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject f d x consent system forbidden response a status code equal to that given
func (o *RejectFDXConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject f d x consent system forbidden response
func (o *RejectFDXConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectFDXConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectFDXConsentSystemForbidden) String() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectFDXConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFDXConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFDXConsentSystemNotFound creates a RejectFDXConsentSystemNotFound with default headers values
func NewRejectFDXConsentSystemNotFound() *RejectFDXConsentSystemNotFound {
	return &RejectFDXConsentSystemNotFound{}
}

/*
RejectFDXConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectFDXConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject f d x consent system not found response has a 2xx status code
func (o *RejectFDXConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject f d x consent system not found response has a 3xx status code
func (o *RejectFDXConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject f d x consent system not found response has a 4xx status code
func (o *RejectFDXConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject f d x consent system not found response has a 5xx status code
func (o *RejectFDXConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject f d x consent system not found response a status code equal to that given
func (o *RejectFDXConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject f d x consent system not found response
func (o *RejectFDXConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectFDXConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectFDXConsentSystemNotFound) String() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectFDXConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFDXConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFDXConsentSystemTooManyRequests creates a RejectFDXConsentSystemTooManyRequests with default headers values
func NewRejectFDXConsentSystemTooManyRequests() *RejectFDXConsentSystemTooManyRequests {
	return &RejectFDXConsentSystemTooManyRequests{}
}

/*
RejectFDXConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectFDXConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject f d x consent system too many requests response has a 2xx status code
func (o *RejectFDXConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject f d x consent system too many requests response has a 3xx status code
func (o *RejectFDXConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject f d x consent system too many requests response has a 4xx status code
func (o *RejectFDXConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject f d x consent system too many requests response has a 5xx status code
func (o *RejectFDXConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject f d x consent system too many requests response a status code equal to that given
func (o *RejectFDXConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject f d x consent system too many requests response
func (o *RejectFDXConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectFDXConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectFDXConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /fdx/fdx/{login}/reject][%d] rejectFDXConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectFDXConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFDXConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
