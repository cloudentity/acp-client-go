// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListClientsReader is a Reader for the ListClients structure.
type ListClientsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListClientsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListClientsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListClientsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListClientsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListClientsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListClientsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListClientsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/clients] listClients", response, response.Code())
	}
}

// NewListClientsOK creates a ListClientsOK with default headers values
func NewListClientsOK() *ListClientsOK {
	return &ListClientsOK{}
}

/*
ListClientsOK describes a response with status code 200, with default header values.

Clients
*/
type ListClientsOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.ClientsForAdmin
}

// IsSuccess returns true when this list clients o k response has a 2xx status code
func (o *ListClientsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list clients o k response has a 3xx status code
func (o *ListClientsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients o k response has a 4xx status code
func (o *ListClientsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list clients o k response has a 5xx status code
func (o *ListClientsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients o k response a status code equal to that given
func (o *ListClientsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list clients o k response
func (o *ListClientsOK) Code() int {
	return 200
}

func (o *ListClientsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsOK  %+v", 200, o.Payload)
}

func (o *ListClientsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsOK  %+v", 200, o.Payload)
}

func (o *ListClientsOK) GetPayload() *models.ClientsForAdmin {
	return o.Payload
}

func (o *ListClientsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.ClientsForAdmin)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClientsBadRequest creates a ListClientsBadRequest with default headers values
func NewListClientsBadRequest() *ListClientsBadRequest {
	return &ListClientsBadRequest{}
}

/*
ListClientsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type ListClientsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list clients bad request response has a 2xx status code
func (o *ListClientsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list clients bad request response has a 3xx status code
func (o *ListClientsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients bad request response has a 4xx status code
func (o *ListClientsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list clients bad request response has a 5xx status code
func (o *ListClientsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients bad request response a status code equal to that given
func (o *ListClientsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the list clients bad request response
func (o *ListClientsBadRequest) Code() int {
	return 400
}

func (o *ListClientsBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsBadRequest  %+v", 400, o.Payload)
}

func (o *ListClientsBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsBadRequest  %+v", 400, o.Payload)
}

func (o *ListClientsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClientsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClientsUnauthorized creates a ListClientsUnauthorized with default headers values
func NewListClientsUnauthorized() *ListClientsUnauthorized {
	return &ListClientsUnauthorized{}
}

/*
ListClientsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListClientsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list clients unauthorized response has a 2xx status code
func (o *ListClientsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list clients unauthorized response has a 3xx status code
func (o *ListClientsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients unauthorized response has a 4xx status code
func (o *ListClientsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list clients unauthorized response has a 5xx status code
func (o *ListClientsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients unauthorized response a status code equal to that given
func (o *ListClientsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list clients unauthorized response
func (o *ListClientsUnauthorized) Code() int {
	return 401
}

func (o *ListClientsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListClientsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListClientsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClientsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClientsForbidden creates a ListClientsForbidden with default headers values
func NewListClientsForbidden() *ListClientsForbidden {
	return &ListClientsForbidden{}
}

/*
ListClientsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListClientsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list clients forbidden response has a 2xx status code
func (o *ListClientsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list clients forbidden response has a 3xx status code
func (o *ListClientsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients forbidden response has a 4xx status code
func (o *ListClientsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list clients forbidden response has a 5xx status code
func (o *ListClientsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients forbidden response a status code equal to that given
func (o *ListClientsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list clients forbidden response
func (o *ListClientsForbidden) Code() int {
	return 403
}

func (o *ListClientsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsForbidden  %+v", 403, o.Payload)
}

func (o *ListClientsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsForbidden  %+v", 403, o.Payload)
}

func (o *ListClientsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClientsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClientsNotFound creates a ListClientsNotFound with default headers values
func NewListClientsNotFound() *ListClientsNotFound {
	return &ListClientsNotFound{}
}

/*
ListClientsNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListClientsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list clients not found response has a 2xx status code
func (o *ListClientsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list clients not found response has a 3xx status code
func (o *ListClientsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients not found response has a 4xx status code
func (o *ListClientsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list clients not found response has a 5xx status code
func (o *ListClientsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients not found response a status code equal to that given
func (o *ListClientsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list clients not found response
func (o *ListClientsNotFound) Code() int {
	return 404
}

func (o *ListClientsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsNotFound  %+v", 404, o.Payload)
}

func (o *ListClientsNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsNotFound  %+v", 404, o.Payload)
}

func (o *ListClientsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClientsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClientsTooManyRequests creates a ListClientsTooManyRequests with default headers values
func NewListClientsTooManyRequests() *ListClientsTooManyRequests {
	return &ListClientsTooManyRequests{}
}

/*
ListClientsTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListClientsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list clients too many requests response has a 2xx status code
func (o *ListClientsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list clients too many requests response has a 3xx status code
func (o *ListClientsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list clients too many requests response has a 4xx status code
func (o *ListClientsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list clients too many requests response has a 5xx status code
func (o *ListClientsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list clients too many requests response a status code equal to that given
func (o *ListClientsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list clients too many requests response
func (o *ListClientsTooManyRequests) Code() int {
	return 429
}

func (o *ListClientsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListClientsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/clients][%d] listClientsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListClientsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClientsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
