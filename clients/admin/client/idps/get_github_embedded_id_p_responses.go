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

// GetGithubEmbeddedIDPReader is a Reader for the GetGithubEmbeddedIDP structure.
type GetGithubEmbeddedIDPReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetGithubEmbeddedIDPReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetGithubEmbeddedIDPOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetGithubEmbeddedIDPUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetGithubEmbeddedIDPForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetGithubEmbeddedIDPNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetGithubEmbeddedIDPTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /servers/{wid}/idps/github_embedded/{iid}] getGithubEmbeddedIDP", response, response.Code())
	}
}

// NewGetGithubEmbeddedIDPOK creates a GetGithubEmbeddedIDPOK with default headers values
func NewGetGithubEmbeddedIDPOK() *GetGithubEmbeddedIDPOK {
	return &GetGithubEmbeddedIDPOK{}
}

/*
GetGithubEmbeddedIDPOK describes a response with status code 200, with default header values.

GithubEmbeddedIDP
*/
type GetGithubEmbeddedIDPOK struct {
	Payload *models.GithubEmbeddedIDP
}

// IsSuccess returns true when this get github embedded Id p o k response has a 2xx status code
func (o *GetGithubEmbeddedIDPOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get github embedded Id p o k response has a 3xx status code
func (o *GetGithubEmbeddedIDPOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github embedded Id p o k response has a 4xx status code
func (o *GetGithubEmbeddedIDPOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get github embedded Id p o k response has a 5xx status code
func (o *GetGithubEmbeddedIDPOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get github embedded Id p o k response a status code equal to that given
func (o *GetGithubEmbeddedIDPOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get github embedded Id p o k response
func (o *GetGithubEmbeddedIDPOK) Code() int {
	return 200
}

func (o *GetGithubEmbeddedIDPOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPOK  %+v", 200, o.Payload)
}

func (o *GetGithubEmbeddedIDPOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPOK  %+v", 200, o.Payload)
}

func (o *GetGithubEmbeddedIDPOK) GetPayload() *models.GithubEmbeddedIDP {
	return o.Payload
}

func (o *GetGithubEmbeddedIDPOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GithubEmbeddedIDP)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGithubEmbeddedIDPUnauthorized creates a GetGithubEmbeddedIDPUnauthorized with default headers values
func NewGetGithubEmbeddedIDPUnauthorized() *GetGithubEmbeddedIDPUnauthorized {
	return &GetGithubEmbeddedIDPUnauthorized{}
}

/*
GetGithubEmbeddedIDPUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetGithubEmbeddedIDPUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get github embedded Id p unauthorized response has a 2xx status code
func (o *GetGithubEmbeddedIDPUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github embedded Id p unauthorized response has a 3xx status code
func (o *GetGithubEmbeddedIDPUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github embedded Id p unauthorized response has a 4xx status code
func (o *GetGithubEmbeddedIDPUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get github embedded Id p unauthorized response has a 5xx status code
func (o *GetGithubEmbeddedIDPUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get github embedded Id p unauthorized response a status code equal to that given
func (o *GetGithubEmbeddedIDPUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get github embedded Id p unauthorized response
func (o *GetGithubEmbeddedIDPUnauthorized) Code() int {
	return 401
}

func (o *GetGithubEmbeddedIDPUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGithubEmbeddedIDPUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPUnauthorized  %+v", 401, o.Payload)
}

func (o *GetGithubEmbeddedIDPUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGithubEmbeddedIDPUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGithubEmbeddedIDPForbidden creates a GetGithubEmbeddedIDPForbidden with default headers values
func NewGetGithubEmbeddedIDPForbidden() *GetGithubEmbeddedIDPForbidden {
	return &GetGithubEmbeddedIDPForbidden{}
}

/*
GetGithubEmbeddedIDPForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetGithubEmbeddedIDPForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get github embedded Id p forbidden response has a 2xx status code
func (o *GetGithubEmbeddedIDPForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github embedded Id p forbidden response has a 3xx status code
func (o *GetGithubEmbeddedIDPForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github embedded Id p forbidden response has a 4xx status code
func (o *GetGithubEmbeddedIDPForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get github embedded Id p forbidden response has a 5xx status code
func (o *GetGithubEmbeddedIDPForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get github embedded Id p forbidden response a status code equal to that given
func (o *GetGithubEmbeddedIDPForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get github embedded Id p forbidden response
func (o *GetGithubEmbeddedIDPForbidden) Code() int {
	return 403
}

func (o *GetGithubEmbeddedIDPForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetGithubEmbeddedIDPForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPForbidden  %+v", 403, o.Payload)
}

func (o *GetGithubEmbeddedIDPForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGithubEmbeddedIDPForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGithubEmbeddedIDPNotFound creates a GetGithubEmbeddedIDPNotFound with default headers values
func NewGetGithubEmbeddedIDPNotFound() *GetGithubEmbeddedIDPNotFound {
	return &GetGithubEmbeddedIDPNotFound{}
}

/*
GetGithubEmbeddedIDPNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetGithubEmbeddedIDPNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get github embedded Id p not found response has a 2xx status code
func (o *GetGithubEmbeddedIDPNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github embedded Id p not found response has a 3xx status code
func (o *GetGithubEmbeddedIDPNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github embedded Id p not found response has a 4xx status code
func (o *GetGithubEmbeddedIDPNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get github embedded Id p not found response has a 5xx status code
func (o *GetGithubEmbeddedIDPNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get github embedded Id p not found response a status code equal to that given
func (o *GetGithubEmbeddedIDPNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get github embedded Id p not found response
func (o *GetGithubEmbeddedIDPNotFound) Code() int {
	return 404
}

func (o *GetGithubEmbeddedIDPNotFound) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetGithubEmbeddedIDPNotFound) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPNotFound  %+v", 404, o.Payload)
}

func (o *GetGithubEmbeddedIDPNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGithubEmbeddedIDPNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetGithubEmbeddedIDPTooManyRequests creates a GetGithubEmbeddedIDPTooManyRequests with default headers values
func NewGetGithubEmbeddedIDPTooManyRequests() *GetGithubEmbeddedIDPTooManyRequests {
	return &GetGithubEmbeddedIDPTooManyRequests{}
}

/*
GetGithubEmbeddedIDPTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetGithubEmbeddedIDPTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get github embedded Id p too many requests response has a 2xx status code
func (o *GetGithubEmbeddedIDPTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get github embedded Id p too many requests response has a 3xx status code
func (o *GetGithubEmbeddedIDPTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get github embedded Id p too many requests response has a 4xx status code
func (o *GetGithubEmbeddedIDPTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get github embedded Id p too many requests response has a 5xx status code
func (o *GetGithubEmbeddedIDPTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get github embedded Id p too many requests response a status code equal to that given
func (o *GetGithubEmbeddedIDPTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get github embedded Id p too many requests response
func (o *GetGithubEmbeddedIDPTooManyRequests) Code() int {
	return 429
}

func (o *GetGithubEmbeddedIDPTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGithubEmbeddedIDPTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/idps/github_embedded/{iid}][%d] getGithubEmbeddedIdPTooManyRequests  %+v", 429, o.Payload)
}

func (o *GetGithubEmbeddedIDPTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetGithubEmbeddedIDPTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
