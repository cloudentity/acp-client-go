// Code generated by go-swagger; DO NOT EDIT.

package claims

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// DeleteClaimReader is a Reader for the DeleteClaim structure.
type DeleteClaimReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteClaimReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteClaimNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteClaimUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteClaimForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteClaimNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteClaimTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /claims/{claim}] deleteClaim", response, response.Code())
	}
}

// NewDeleteClaimNoContent creates a DeleteClaimNoContent with default headers values
func NewDeleteClaimNoContent() *DeleteClaimNoContent {
	return &DeleteClaimNoContent{}
}

/*
DeleteClaimNoContent describes a response with status code 204, with default header values.

	Claim has been deleted
*/
type DeleteClaimNoContent struct {
}

// IsSuccess returns true when this delete claim no content response has a 2xx status code
func (o *DeleteClaimNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete claim no content response has a 3xx status code
func (o *DeleteClaimNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete claim no content response has a 4xx status code
func (o *DeleteClaimNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete claim no content response has a 5xx status code
func (o *DeleteClaimNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete claim no content response a status code equal to that given
func (o *DeleteClaimNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete claim no content response
func (o *DeleteClaimNoContent) Code() int {
	return 204
}

func (o *DeleteClaimNoContent) Error() string {
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimNoContent", 204)
}

func (o *DeleteClaimNoContent) String() string {
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimNoContent", 204)
}

func (o *DeleteClaimNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteClaimUnauthorized creates a DeleteClaimUnauthorized with default headers values
func NewDeleteClaimUnauthorized() *DeleteClaimUnauthorized {
	return &DeleteClaimUnauthorized{}
}

/*
DeleteClaimUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteClaimUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete claim unauthorized response has a 2xx status code
func (o *DeleteClaimUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete claim unauthorized response has a 3xx status code
func (o *DeleteClaimUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete claim unauthorized response has a 4xx status code
func (o *DeleteClaimUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete claim unauthorized response has a 5xx status code
func (o *DeleteClaimUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete claim unauthorized response a status code equal to that given
func (o *DeleteClaimUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete claim unauthorized response
func (o *DeleteClaimUnauthorized) Code() int {
	return 401
}

func (o *DeleteClaimUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimUnauthorized %s", 401, payload)
}

func (o *DeleteClaimUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimUnauthorized %s", 401, payload)
}

func (o *DeleteClaimUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClaimUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClaimForbidden creates a DeleteClaimForbidden with default headers values
func NewDeleteClaimForbidden() *DeleteClaimForbidden {
	return &DeleteClaimForbidden{}
}

/*
DeleteClaimForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteClaimForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete claim forbidden response has a 2xx status code
func (o *DeleteClaimForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete claim forbidden response has a 3xx status code
func (o *DeleteClaimForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete claim forbidden response has a 4xx status code
func (o *DeleteClaimForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete claim forbidden response has a 5xx status code
func (o *DeleteClaimForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete claim forbidden response a status code equal to that given
func (o *DeleteClaimForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete claim forbidden response
func (o *DeleteClaimForbidden) Code() int {
	return 403
}

func (o *DeleteClaimForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimForbidden %s", 403, payload)
}

func (o *DeleteClaimForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimForbidden %s", 403, payload)
}

func (o *DeleteClaimForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClaimForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClaimNotFound creates a DeleteClaimNotFound with default headers values
func NewDeleteClaimNotFound() *DeleteClaimNotFound {
	return &DeleteClaimNotFound{}
}

/*
DeleteClaimNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteClaimNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete claim not found response has a 2xx status code
func (o *DeleteClaimNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete claim not found response has a 3xx status code
func (o *DeleteClaimNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete claim not found response has a 4xx status code
func (o *DeleteClaimNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete claim not found response has a 5xx status code
func (o *DeleteClaimNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete claim not found response a status code equal to that given
func (o *DeleteClaimNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete claim not found response
func (o *DeleteClaimNotFound) Code() int {
	return 404
}

func (o *DeleteClaimNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimNotFound %s", 404, payload)
}

func (o *DeleteClaimNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimNotFound %s", 404, payload)
}

func (o *DeleteClaimNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClaimNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteClaimTooManyRequests creates a DeleteClaimTooManyRequests with default headers values
func NewDeleteClaimTooManyRequests() *DeleteClaimTooManyRequests {
	return &DeleteClaimTooManyRequests{}
}

/*
DeleteClaimTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteClaimTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete claim too many requests response has a 2xx status code
func (o *DeleteClaimTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete claim too many requests response has a 3xx status code
func (o *DeleteClaimTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete claim too many requests response has a 4xx status code
func (o *DeleteClaimTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete claim too many requests response has a 5xx status code
func (o *DeleteClaimTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete claim too many requests response a status code equal to that given
func (o *DeleteClaimTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete claim too many requests response
func (o *DeleteClaimTooManyRequests) Code() int {
	return 429
}

func (o *DeleteClaimTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimTooManyRequests %s", 429, payload)
}

func (o *DeleteClaimTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /claims/{claim}][%d] deleteClaimTooManyRequests %s", 429, payload)
}

func (o *DeleteClaimTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteClaimTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
