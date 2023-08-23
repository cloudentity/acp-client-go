// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/fdx/models"
)

// FDXDynamicClientRegistrationDeleteReader is a Reader for the FDXDynamicClientRegistrationDelete structure.
type FDXDynamicClientRegistrationDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *FDXDynamicClientRegistrationDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewFDXDynamicClientRegistrationDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewFDXDynamicClientRegistrationDeleteBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewFDXDynamicClientRegistrationDeleteUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewFDXDynamicClientRegistrationDeleteForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewFDXDynamicClientRegistrationDeleteNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewFDXDynamicClientRegistrationDeleteNoContent creates a FDXDynamicClientRegistrationDeleteNoContent with default headers values
func NewFDXDynamicClientRegistrationDeleteNoContent() *FDXDynamicClientRegistrationDeleteNoContent {
	return &FDXDynamicClientRegistrationDeleteNoContent{}
}

/*
FDXDynamicClientRegistrationDeleteNoContent describes a response with status code 204, with default header values.

	Client has been deleted
*/
type FDXDynamicClientRegistrationDeleteNoContent struct {
}

// IsSuccess returns true when this f d x dynamic client registration delete no content response has a 2xx status code
func (o *FDXDynamicClientRegistrationDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this f d x dynamic client registration delete no content response has a 3xx status code
func (o *FDXDynamicClientRegistrationDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x dynamic client registration delete no content response has a 4xx status code
func (o *FDXDynamicClientRegistrationDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this f d x dynamic client registration delete no content response has a 5xx status code
func (o *FDXDynamicClientRegistrationDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x dynamic client registration delete no content response a status code equal to that given
func (o *FDXDynamicClientRegistrationDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the f d x dynamic client registration delete no content response
func (o *FDXDynamicClientRegistrationDeleteNoContent) Code() int {
	return 204
}

func (o *FDXDynamicClientRegistrationDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteNoContent ", 204)
}

func (o *FDXDynamicClientRegistrationDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteNoContent ", 204)
}

func (o *FDXDynamicClientRegistrationDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewFDXDynamicClientRegistrationDeleteBadRequest creates a FDXDynamicClientRegistrationDeleteBadRequest with default headers values
func NewFDXDynamicClientRegistrationDeleteBadRequest() *FDXDynamicClientRegistrationDeleteBadRequest {
	return &FDXDynamicClientRegistrationDeleteBadRequest{}
}

/*
FDXDynamicClientRegistrationDeleteBadRequest describes a response with status code 400, with default header values.

RFC6749 error
*/
type FDXDynamicClientRegistrationDeleteBadRequest struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this f d x dynamic client registration delete bad request response has a 2xx status code
func (o *FDXDynamicClientRegistrationDeleteBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x dynamic client registration delete bad request response has a 3xx status code
func (o *FDXDynamicClientRegistrationDeleteBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x dynamic client registration delete bad request response has a 4xx status code
func (o *FDXDynamicClientRegistrationDeleteBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x dynamic client registration delete bad request response has a 5xx status code
func (o *FDXDynamicClientRegistrationDeleteBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x dynamic client registration delete bad request response a status code equal to that given
func (o *FDXDynamicClientRegistrationDeleteBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the f d x dynamic client registration delete bad request response
func (o *FDXDynamicClientRegistrationDeleteBadRequest) Code() int {
	return 400
}

func (o *FDXDynamicClientRegistrationDeleteBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteBadRequest  %+v", 400, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteBadRequest) String() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteBadRequest  %+v", 400, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteBadRequest) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *FDXDynamicClientRegistrationDeleteBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXDynamicClientRegistrationDeleteUnauthorized creates a FDXDynamicClientRegistrationDeleteUnauthorized with default headers values
func NewFDXDynamicClientRegistrationDeleteUnauthorized() *FDXDynamicClientRegistrationDeleteUnauthorized {
	return &FDXDynamicClientRegistrationDeleteUnauthorized{}
}

/*
FDXDynamicClientRegistrationDeleteUnauthorized describes a response with status code 401, with default header values.

RFC6749 error
*/
type FDXDynamicClientRegistrationDeleteUnauthorized struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this f d x dynamic client registration delete unauthorized response has a 2xx status code
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x dynamic client registration delete unauthorized response has a 3xx status code
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x dynamic client registration delete unauthorized response has a 4xx status code
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x dynamic client registration delete unauthorized response has a 5xx status code
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x dynamic client registration delete unauthorized response a status code equal to that given
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the f d x dynamic client registration delete unauthorized response
func (o *FDXDynamicClientRegistrationDeleteUnauthorized) Code() int {
	return 401
}

func (o *FDXDynamicClientRegistrationDeleteUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteUnauthorized  %+v", 401, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteUnauthorized  %+v", 401, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteUnauthorized) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *FDXDynamicClientRegistrationDeleteUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXDynamicClientRegistrationDeleteForbidden creates a FDXDynamicClientRegistrationDeleteForbidden with default headers values
func NewFDXDynamicClientRegistrationDeleteForbidden() *FDXDynamicClientRegistrationDeleteForbidden {
	return &FDXDynamicClientRegistrationDeleteForbidden{}
}

/*
FDXDynamicClientRegistrationDeleteForbidden describes a response with status code 403, with default header values.

RFC6749 error
*/
type FDXDynamicClientRegistrationDeleteForbidden struct {
	Payload *models.RFC6749Error
}

// IsSuccess returns true when this f d x dynamic client registration delete forbidden response has a 2xx status code
func (o *FDXDynamicClientRegistrationDeleteForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x dynamic client registration delete forbidden response has a 3xx status code
func (o *FDXDynamicClientRegistrationDeleteForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x dynamic client registration delete forbidden response has a 4xx status code
func (o *FDXDynamicClientRegistrationDeleteForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x dynamic client registration delete forbidden response has a 5xx status code
func (o *FDXDynamicClientRegistrationDeleteForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x dynamic client registration delete forbidden response a status code equal to that given
func (o *FDXDynamicClientRegistrationDeleteForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the f d x dynamic client registration delete forbidden response
func (o *FDXDynamicClientRegistrationDeleteForbidden) Code() int {
	return 403
}

func (o *FDXDynamicClientRegistrationDeleteForbidden) Error() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteForbidden  %+v", 403, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteForbidden) String() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteForbidden  %+v", 403, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteForbidden) GetPayload() *models.RFC6749Error {
	return o.Payload
}

func (o *FDXDynamicClientRegistrationDeleteForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RFC6749Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewFDXDynamicClientRegistrationDeleteNotFound creates a FDXDynamicClientRegistrationDeleteNotFound with default headers values
func NewFDXDynamicClientRegistrationDeleteNotFound() *FDXDynamicClientRegistrationDeleteNotFound {
	return &FDXDynamicClientRegistrationDeleteNotFound{}
}

/*
FDXDynamicClientRegistrationDeleteNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type FDXDynamicClientRegistrationDeleteNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this f d x dynamic client registration delete not found response has a 2xx status code
func (o *FDXDynamicClientRegistrationDeleteNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this f d x dynamic client registration delete not found response has a 3xx status code
func (o *FDXDynamicClientRegistrationDeleteNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this f d x dynamic client registration delete not found response has a 4xx status code
func (o *FDXDynamicClientRegistrationDeleteNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this f d x dynamic client registration delete not found response has a 5xx status code
func (o *FDXDynamicClientRegistrationDeleteNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this f d x dynamic client registration delete not found response a status code equal to that given
func (o *FDXDynamicClientRegistrationDeleteNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the f d x dynamic client registration delete not found response
func (o *FDXDynamicClientRegistrationDeleteNotFound) Code() int {
	return 404
}

func (o *FDXDynamicClientRegistrationDeleteNotFound) Error() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteNotFound  %+v", 404, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteNotFound) String() string {
	return fmt.Sprintf("[DELETE /fdx/dcr/register/{cid}][%d] fDXDynamicClientRegistrationDeleteNotFound  %+v", 404, o.Payload)
}

func (o *FDXDynamicClientRegistrationDeleteNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *FDXDynamicClientRegistrationDeleteNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}