// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// RejectOBBRCustomerDataAccessConsentSystemReader is a Reader for the RejectOBBRCustomerDataAccessConsentSystem structure.
type RejectOBBRCustomerDataAccessConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectOBBRCustomerDataAccessConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectOBBRCustomerDataAccessConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectOBBRCustomerDataAccessConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectOBBRCustomerDataAccessConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectOBBRCustomerDataAccessConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectOBBRCustomerDataAccessConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking-brasil/consent/{login}/reject] rejectOBBRCustomerDataAccessConsentSystem", response, response.Code())
	}
}

// NewRejectOBBRCustomerDataAccessConsentSystemOK creates a RejectOBBRCustomerDataAccessConsentSystemOK with default headers values
func NewRejectOBBRCustomerDataAccessConsentSystemOK() *RejectOBBRCustomerDataAccessConsentSystemOK {
	return &RejectOBBRCustomerDataAccessConsentSystemOK{}
}

/*
RejectOBBRCustomerDataAccessConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectOBBRCustomerDataAccessConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject o b b r customer data access consent system o k response has a 2xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject o b b r customer data access consent system o k response has a 3xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer data access consent system o k response has a 4xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject o b b r customer data access consent system o k response has a 5xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer data access consent system o k response a status code equal to that given
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject o b b r customer data access consent system o k response
func (o *RejectOBBRCustomerDataAccessConsentSystemOK) Code() int {
	return 200
}

func (o *RejectOBBRCustomerDataAccessConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemOK) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectOBBRCustomerDataAccessConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerDataAccessConsentSystemUnauthorized creates a RejectOBBRCustomerDataAccessConsentSystemUnauthorized with default headers values
func NewRejectOBBRCustomerDataAccessConsentSystemUnauthorized() *RejectOBBRCustomerDataAccessConsentSystemUnauthorized {
	return &RejectOBBRCustomerDataAccessConsentSystemUnauthorized{}
}

/*
RejectOBBRCustomerDataAccessConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectOBBRCustomerDataAccessConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer data access consent system unauthorized response has a 2xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer data access consent system unauthorized response has a 3xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer data access consent system unauthorized response has a 4xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer data access consent system unauthorized response has a 5xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer data access consent system unauthorized response a status code equal to that given
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject o b b r customer data access consent system unauthorized response
func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerDataAccessConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerDataAccessConsentSystemForbidden creates a RejectOBBRCustomerDataAccessConsentSystemForbidden with default headers values
func NewRejectOBBRCustomerDataAccessConsentSystemForbidden() *RejectOBBRCustomerDataAccessConsentSystemForbidden {
	return &RejectOBBRCustomerDataAccessConsentSystemForbidden{}
}

/*
RejectOBBRCustomerDataAccessConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectOBBRCustomerDataAccessConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer data access consent system forbidden response has a 2xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer data access consent system forbidden response has a 3xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer data access consent system forbidden response has a 4xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer data access consent system forbidden response has a 5xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer data access consent system forbidden response a status code equal to that given
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject o b b r customer data access consent system forbidden response
func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerDataAccessConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerDataAccessConsentSystemNotFound creates a RejectOBBRCustomerDataAccessConsentSystemNotFound with default headers values
func NewRejectOBBRCustomerDataAccessConsentSystemNotFound() *RejectOBBRCustomerDataAccessConsentSystemNotFound {
	return &RejectOBBRCustomerDataAccessConsentSystemNotFound{}
}

/*
RejectOBBRCustomerDataAccessConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectOBBRCustomerDataAccessConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer data access consent system not found response has a 2xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer data access consent system not found response has a 3xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer data access consent system not found response has a 4xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer data access consent system not found response has a 5xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer data access consent system not found response a status code equal to that given
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject o b b r customer data access consent system not found response
func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerDataAccessConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerDataAccessConsentSystemTooManyRequests creates a RejectOBBRCustomerDataAccessConsentSystemTooManyRequests with default headers values
func NewRejectOBBRCustomerDataAccessConsentSystemTooManyRequests() *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests {
	return &RejectOBBRCustomerDataAccessConsentSystemTooManyRequests{}
}

/*
RejectOBBRCustomerDataAccessConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectOBBRCustomerDataAccessConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer data access consent system too many requests response has a 2xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer data access consent system too many requests response has a 3xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer data access consent system too many requests response has a 4xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer data access consent system too many requests response has a 5xx status code
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer data access consent system too many requests response a status code equal to that given
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject o b b r customer data access consent system too many requests response
func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/consent/{login}/reject][%d] rejectOBBRCustomerDataAccessConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerDataAccessConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}