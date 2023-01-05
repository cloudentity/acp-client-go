// Code generated by go-swagger; DO NOT EDIT.

package idps

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListIDPsReader is a Reader for the ListIDPs structure.
type ListIDPsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListIDPsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListIDPsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListIDPsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewListIDPsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListIDPsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListIDPsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListIDPsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListIDPsOK creates a ListIDPsOK with default headers values
func NewListIDPsOK() *ListIDPsOK {
	return &ListIDPsOK{}
}

/*
ListIDPsOK describes a response with status code 200, with default header values.

IDP
*/
type ListIDPsOK struct {
	Payload *models.IDPsResponse
}

// IsSuccess returns true when this list Id ps o k response has a 2xx status code
func (o *ListIDPsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list Id ps o k response has a 3xx status code
func (o *ListIDPsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps o k response has a 4xx status code
func (o *ListIDPsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list Id ps o k response has a 5xx status code
func (o *ListIDPsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps o k response a status code equal to that given
func (o *ListIDPsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListIDPsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsOK  %+v", 200, o.Payload)
}

func (o *ListIDPsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsOK  %+v", 200, o.Payload)
}

func (o *ListIDPsOK) GetPayload() *models.IDPsResponse {
	return o.Payload
}

func (o *ListIDPsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IDPsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsBadRequest creates a ListIDPsBadRequest with default headers values
func NewListIDPsBadRequest() *ListIDPsBadRequest {
	return &ListIDPsBadRequest{}
}

/*
ListIDPsBadRequest describes a response with status code 400, with default header values.

HttpError
*/
type ListIDPsBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps bad request response has a 2xx status code
func (o *ListIDPsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps bad request response has a 3xx status code
func (o *ListIDPsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps bad request response has a 4xx status code
func (o *ListIDPsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps bad request response has a 5xx status code
func (o *ListIDPsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps bad request response a status code equal to that given
func (o *ListIDPsBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *ListIDPsBadRequest) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsBadRequest  %+v", 400, o.Payload)
}

func (o *ListIDPsBadRequest) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsBadRequest  %+v", 400, o.Payload)
}

func (o *ListIDPsBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsUnauthorized creates a ListIDPsUnauthorized with default headers values
func NewListIDPsUnauthorized() *ListIDPsUnauthorized {
	return &ListIDPsUnauthorized{}
}

/*
ListIDPsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListIDPsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps unauthorized response has a 2xx status code
func (o *ListIDPsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps unauthorized response has a 3xx status code
func (o *ListIDPsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps unauthorized response has a 4xx status code
func (o *ListIDPsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps unauthorized response has a 5xx status code
func (o *ListIDPsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps unauthorized response a status code equal to that given
func (o *ListIDPsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListIDPsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIDPsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIDPsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsForbidden creates a ListIDPsForbidden with default headers values
func NewListIDPsForbidden() *ListIDPsForbidden {
	return &ListIDPsForbidden{}
}

/*
ListIDPsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListIDPsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps forbidden response has a 2xx status code
func (o *ListIDPsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps forbidden response has a 3xx status code
func (o *ListIDPsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps forbidden response has a 4xx status code
func (o *ListIDPsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps forbidden response has a 5xx status code
func (o *ListIDPsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps forbidden response a status code equal to that given
func (o *ListIDPsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListIDPsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsForbidden  %+v", 403, o.Payload)
}

func (o *ListIDPsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsForbidden  %+v", 403, o.Payload)
}

func (o *ListIDPsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsNotFound creates a ListIDPsNotFound with default headers values
func NewListIDPsNotFound() *ListIDPsNotFound {
	return &ListIDPsNotFound{}
}

/*
ListIDPsNotFound describes a response with status code 404, with default header values.

HttpError
*/
type ListIDPsNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps not found response has a 2xx status code
func (o *ListIDPsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps not found response has a 3xx status code
func (o *ListIDPsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps not found response has a 4xx status code
func (o *ListIDPsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps not found response has a 5xx status code
func (o *ListIDPsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps not found response a status code equal to that given
func (o *ListIDPsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ListIDPsNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsNotFound  %+v", 404, o.Payload)
}

func (o *ListIDPsNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsNotFound  %+v", 404, o.Payload)
}

func (o *ListIDPsNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIDPsTooManyRequests creates a ListIDPsTooManyRequests with default headers values
func NewListIDPsTooManyRequests() *ListIDPsTooManyRequests {
	return &ListIDPsTooManyRequests{}
}

/*
ListIDPsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListIDPsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list Id ps too many requests response has a 2xx status code
func (o *ListIDPsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list Id ps too many requests response has a 3xx status code
func (o *ListIDPsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list Id ps too many requests response has a 4xx status code
func (o *ListIDPsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list Id ps too many requests response has a 5xx status code
func (o *ListIDPsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list Id ps too many requests response a status code equal to that given
func (o *ListIDPsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListIDPsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIDPsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps][%d] listIdPsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIDPsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIDPsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
