// Code generated by go-swagger; DO NOT EDIT.

package audit_events

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListAuditEventsReader is a Reader for the ListAuditEvents structure.
type ListAuditEventsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListAuditEventsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListAuditEventsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListAuditEventsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListAuditEventsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListAuditEventsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListAuditEventsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListAuditEventsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListAuditEventsOK creates a ListAuditEventsOK with default headers values
func NewListAuditEventsOK() *ListAuditEventsOK {
	return &ListAuditEventsOK{}
}

/*
ListAuditEventsOK describes a response with status code 200, with default header values.

AuditEvents
*/
type ListAuditEventsOK struct {
	Payload *models.AuditEvents
}

// IsSuccess returns true when this list audit events o k response has a 2xx status code
func (o *ListAuditEventsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list audit events o k response has a 3xx status code
func (o *ListAuditEventsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events o k response has a 4xx status code
func (o *ListAuditEventsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list audit events o k response has a 5xx status code
func (o *ListAuditEventsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events o k response a status code equal to that given
func (o *ListAuditEventsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListAuditEventsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsOK  %+v", 200, o.Payload)
}

func (o *ListAuditEventsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsOK  %+v", 200, o.Payload)
}

func (o *ListAuditEventsOK) GetPayload() *models.AuditEvents {
	return o.Payload
}

func (o *ListAuditEventsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AuditEvents)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuditEventsBadRequest creates a ListAuditEventsBadRequest with default headers values
func NewListAuditEventsBadRequest() *ListAuditEventsBadRequest {
	return &ListAuditEventsBadRequest{}
}

/*
ListAuditEventsBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ListAuditEventsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list audit events bad request response has a 2xx status code
func (o *ListAuditEventsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list audit events bad request response has a 3xx status code
func (o *ListAuditEventsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events bad request response has a 4xx status code
func (o *ListAuditEventsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list audit events bad request response has a 5xx status code
func (o *ListAuditEventsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events bad request response a status code equal to that given
func (o *ListAuditEventsBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *ListAuditEventsBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsBadRequest  %+v", 400, o.Payload)
}

func (o *ListAuditEventsBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsBadRequest  %+v", 400, o.Payload)
}

func (o *ListAuditEventsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuditEventsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuditEventsUnauthorized creates a ListAuditEventsUnauthorized with default headers values
func NewListAuditEventsUnauthorized() *ListAuditEventsUnauthorized {
	return &ListAuditEventsUnauthorized{}
}

/*
ListAuditEventsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListAuditEventsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list audit events unauthorized response has a 2xx status code
func (o *ListAuditEventsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list audit events unauthorized response has a 3xx status code
func (o *ListAuditEventsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events unauthorized response has a 4xx status code
func (o *ListAuditEventsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list audit events unauthorized response has a 5xx status code
func (o *ListAuditEventsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events unauthorized response a status code equal to that given
func (o *ListAuditEventsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListAuditEventsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListAuditEventsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListAuditEventsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuditEventsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuditEventsForbidden creates a ListAuditEventsForbidden with default headers values
func NewListAuditEventsForbidden() *ListAuditEventsForbidden {
	return &ListAuditEventsForbidden{}
}

/*
ListAuditEventsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListAuditEventsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list audit events forbidden response has a 2xx status code
func (o *ListAuditEventsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list audit events forbidden response has a 3xx status code
func (o *ListAuditEventsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events forbidden response has a 4xx status code
func (o *ListAuditEventsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list audit events forbidden response has a 5xx status code
func (o *ListAuditEventsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events forbidden response a status code equal to that given
func (o *ListAuditEventsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListAuditEventsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsForbidden  %+v", 403, o.Payload)
}

func (o *ListAuditEventsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsForbidden  %+v", 403, o.Payload)
}

func (o *ListAuditEventsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuditEventsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuditEventsNotFound creates a ListAuditEventsNotFound with default headers values
func NewListAuditEventsNotFound() *ListAuditEventsNotFound {
	return &ListAuditEventsNotFound{}
}

/*
ListAuditEventsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListAuditEventsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list audit events not found response has a 2xx status code
func (o *ListAuditEventsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list audit events not found response has a 3xx status code
func (o *ListAuditEventsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events not found response has a 4xx status code
func (o *ListAuditEventsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list audit events not found response has a 5xx status code
func (o *ListAuditEventsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events not found response a status code equal to that given
func (o *ListAuditEventsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListAuditEventsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsNotFound  %+v", 404, o.Payload)
}

func (o *ListAuditEventsNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsNotFound  %+v", 404, o.Payload)
}

func (o *ListAuditEventsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuditEventsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListAuditEventsTooManyRequests creates a ListAuditEventsTooManyRequests with default headers values
func NewListAuditEventsTooManyRequests() *ListAuditEventsTooManyRequests {
	return &ListAuditEventsTooManyRequests{}
}

/*
ListAuditEventsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListAuditEventsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list audit events too many requests response has a 2xx status code
func (o *ListAuditEventsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list audit events too many requests response has a 3xx status code
func (o *ListAuditEventsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list audit events too many requests response has a 4xx status code
func (o *ListAuditEventsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list audit events too many requests response has a 5xx status code
func (o *ListAuditEventsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list audit events too many requests response a status code equal to that given
func (o *ListAuditEventsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListAuditEventsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListAuditEventsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/audit-events][%d] listAuditEventsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListAuditEventsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListAuditEventsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
