// Code generated by go-swagger; DO NOT EDIT.

package claims

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListClaimsReader is a Reader for the ListClaims structure.
type ListClaimsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListClaimsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListClaimsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListClaimsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListClaimsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListClaimsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListClaimsOK creates a ListClaimsOK with default headers values
func NewListClaimsOK() *ListClaimsOK {
	return &ListClaimsOK{}
}

/*
ListClaimsOK describes a response with status code 200, with default header values.

Claims
*/
type ListClaimsOK struct {
	Payload *models.Claims
}

// IsSuccess returns true when this list claims o k response has a 2xx status code
func (o *ListClaimsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list claims o k response has a 3xx status code
func (o *ListClaimsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list claims o k response has a 4xx status code
func (o *ListClaimsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list claims o k response has a 5xx status code
func (o *ListClaimsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list claims o k response a status code equal to that given
func (o *ListClaimsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListClaimsOK) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsOK  %+v", 200, o.Payload)
}

func (o *ListClaimsOK) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsOK  %+v", 200, o.Payload)
}

func (o *ListClaimsOK) GetPayload() *models.Claims {
	return o.Payload
}

func (o *ListClaimsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Claims)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClaimsUnauthorized creates a ListClaimsUnauthorized with default headers values
func NewListClaimsUnauthorized() *ListClaimsUnauthorized {
	return &ListClaimsUnauthorized{}
}

/*
ListClaimsUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type ListClaimsUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list claims unauthorized response has a 2xx status code
func (o *ListClaimsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list claims unauthorized response has a 3xx status code
func (o *ListClaimsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list claims unauthorized response has a 4xx status code
func (o *ListClaimsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list claims unauthorized response has a 5xx status code
func (o *ListClaimsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list claims unauthorized response a status code equal to that given
func (o *ListClaimsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ListClaimsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListClaimsUnauthorized) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsUnauthorized  %+v", 401, o.Payload)
}

func (o *ListClaimsUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClaimsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClaimsForbidden creates a ListClaimsForbidden with default headers values
func NewListClaimsForbidden() *ListClaimsForbidden {
	return &ListClaimsForbidden{}
}

/*
ListClaimsForbidden describes a response with status code 403, with default header values.

HttpError
*/
type ListClaimsForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list claims forbidden response has a 2xx status code
func (o *ListClaimsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list claims forbidden response has a 3xx status code
func (o *ListClaimsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list claims forbidden response has a 4xx status code
func (o *ListClaimsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list claims forbidden response has a 5xx status code
func (o *ListClaimsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list claims forbidden response a status code equal to that given
func (o *ListClaimsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *ListClaimsForbidden) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsForbidden  %+v", 403, o.Payload)
}

func (o *ListClaimsForbidden) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsForbidden  %+v", 403, o.Payload)
}

func (o *ListClaimsForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClaimsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListClaimsTooManyRequests creates a ListClaimsTooManyRequests with default headers values
func NewListClaimsTooManyRequests() *ListClaimsTooManyRequests {
	return &ListClaimsTooManyRequests{}
}

/*
ListClaimsTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type ListClaimsTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list claims too many requests response has a 2xx status code
func (o *ListClaimsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list claims too many requests response has a 3xx status code
func (o *ListClaimsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list claims too many requests response has a 4xx status code
func (o *ListClaimsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list claims too many requests response has a 5xx status code
func (o *ListClaimsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list claims too many requests response a status code equal to that given
func (o *ListClaimsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ListClaimsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListClaimsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /servers/{wid}/claims][%d] listClaimsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListClaimsTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListClaimsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
