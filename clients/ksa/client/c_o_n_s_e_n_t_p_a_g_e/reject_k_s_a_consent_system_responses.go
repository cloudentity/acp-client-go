// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/ksa/models"
)

// RejectKSAConsentSystemReader is a Reader for the RejectKSAConsentSystem structure.
type RejectKSAConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectKSAConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectKSAConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectKSAConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectKSAConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectKSAConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectKSAConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectKSAConsentSystemOK creates a RejectKSAConsentSystemOK with default headers values
func NewRejectKSAConsentSystemOK() *RejectKSAConsentSystemOK {
	return &RejectKSAConsentSystemOK{}
}

/*
RejectKSAConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectKSAConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject k s a consent system o k response has a 2xx status code
func (o *RejectKSAConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject k s a consent system o k response has a 3xx status code
func (o *RejectKSAConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject k s a consent system o k response has a 4xx status code
func (o *RejectKSAConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject k s a consent system o k response has a 5xx status code
func (o *RejectKSAConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject k s a consent system o k response a status code equal to that given
func (o *RejectKSAConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject k s a consent system o k response
func (o *RejectKSAConsentSystemOK) Code() int {
	return 200
}

func (o *RejectKSAConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectKSAConsentSystemOK) String() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectKSAConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectKSAConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectKSAConsentSystemUnauthorized creates a RejectKSAConsentSystemUnauthorized with default headers values
func NewRejectKSAConsentSystemUnauthorized() *RejectKSAConsentSystemUnauthorized {
	return &RejectKSAConsentSystemUnauthorized{}
}

/*
RejectKSAConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectKSAConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject k s a consent system unauthorized response has a 2xx status code
func (o *RejectKSAConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject k s a consent system unauthorized response has a 3xx status code
func (o *RejectKSAConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject k s a consent system unauthorized response has a 4xx status code
func (o *RejectKSAConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject k s a consent system unauthorized response has a 5xx status code
func (o *RejectKSAConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject k s a consent system unauthorized response a status code equal to that given
func (o *RejectKSAConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject k s a consent system unauthorized response
func (o *RejectKSAConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectKSAConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectKSAConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectKSAConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectKSAConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectKSAConsentSystemForbidden creates a RejectKSAConsentSystemForbidden with default headers values
func NewRejectKSAConsentSystemForbidden() *RejectKSAConsentSystemForbidden {
	return &RejectKSAConsentSystemForbidden{}
}

/*
RejectKSAConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectKSAConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject k s a consent system forbidden response has a 2xx status code
func (o *RejectKSAConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject k s a consent system forbidden response has a 3xx status code
func (o *RejectKSAConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject k s a consent system forbidden response has a 4xx status code
func (o *RejectKSAConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject k s a consent system forbidden response has a 5xx status code
func (o *RejectKSAConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject k s a consent system forbidden response a status code equal to that given
func (o *RejectKSAConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject k s a consent system forbidden response
func (o *RejectKSAConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectKSAConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectKSAConsentSystemForbidden) String() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectKSAConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectKSAConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectKSAConsentSystemNotFound creates a RejectKSAConsentSystemNotFound with default headers values
func NewRejectKSAConsentSystemNotFound() *RejectKSAConsentSystemNotFound {
	return &RejectKSAConsentSystemNotFound{}
}

/*
RejectKSAConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectKSAConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject k s a consent system not found response has a 2xx status code
func (o *RejectKSAConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject k s a consent system not found response has a 3xx status code
func (o *RejectKSAConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject k s a consent system not found response has a 4xx status code
func (o *RejectKSAConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject k s a consent system not found response has a 5xx status code
func (o *RejectKSAConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject k s a consent system not found response a status code equal to that given
func (o *RejectKSAConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject k s a consent system not found response
func (o *RejectKSAConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectKSAConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectKSAConsentSystemNotFound) String() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectKSAConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectKSAConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectKSAConsentSystemTooManyRequests creates a RejectKSAConsentSystemTooManyRequests with default headers values
func NewRejectKSAConsentSystemTooManyRequests() *RejectKSAConsentSystemTooManyRequests {
	return &RejectKSAConsentSystemTooManyRequests{}
}

/*
RejectKSAConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectKSAConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject k s a consent system too many requests response has a 2xx status code
func (o *RejectKSAConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject k s a consent system too many requests response has a 3xx status code
func (o *RejectKSAConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject k s a consent system too many requests response has a 4xx status code
func (o *RejectKSAConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject k s a consent system too many requests response has a 5xx status code
func (o *RejectKSAConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject k s a consent system too many requests response a status code equal to that given
func (o *RejectKSAConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject k s a consent system too many requests response
func (o *RejectKSAConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectKSAConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectKSAConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /ksa/consent/{login}/reject][%d] rejectKSAConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectKSAConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectKSAConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}