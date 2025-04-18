// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/cdr/models"
)

// RevokeCDRArrangementByIDReader is a Reader for the RevokeCDRArrangementByID structure.
type RevokeCDRArrangementByIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RevokeCDRArrangementByIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRevokeCDRArrangementByIDNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRevokeCDRArrangementByIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRevokeCDRArrangementByIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRevokeCDRArrangementByIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRevokeCDRArrangementByIDUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRevokeCDRArrangementByIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}] revokeCDRArrangementByID", response, response.Code())
	}
}

// NewRevokeCDRArrangementByIDNoContent creates a RevokeCDRArrangementByIDNoContent with default headers values
func NewRevokeCDRArrangementByIDNoContent() *RevokeCDRArrangementByIDNoContent {
	return &RevokeCDRArrangementByIDNoContent{}
}

/*
RevokeCDRArrangementByIDNoContent describes a response with status code 204, with default header values.

	Arrangement revoked
*/
type RevokeCDRArrangementByIDNoContent struct {
}

// IsSuccess returns true when this revoke c d r arrangement by Id no content response has a 2xx status code
func (o *RevokeCDRArrangementByIDNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this revoke c d r arrangement by Id no content response has a 3xx status code
func (o *RevokeCDRArrangementByIDNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id no content response has a 4xx status code
func (o *RevokeCDRArrangementByIDNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this revoke c d r arrangement by Id no content response has a 5xx status code
func (o *RevokeCDRArrangementByIDNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id no content response a status code equal to that given
func (o *RevokeCDRArrangementByIDNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the revoke c d r arrangement by Id no content response
func (o *RevokeCDRArrangementByIDNoContent) Code() int {
	return 204
}

func (o *RevokeCDRArrangementByIDNoContent) Error() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdNoContent", 204)
}

func (o *RevokeCDRArrangementByIDNoContent) String() string {
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdNoContent", 204)
}

func (o *RevokeCDRArrangementByIDNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRevokeCDRArrangementByIDUnauthorized creates a RevokeCDRArrangementByIDUnauthorized with default headers values
func NewRevokeCDRArrangementByIDUnauthorized() *RevokeCDRArrangementByIDUnauthorized {
	return &RevokeCDRArrangementByIDUnauthorized{}
}

/*
RevokeCDRArrangementByIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RevokeCDRArrangementByIDUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke c d r arrangement by Id unauthorized response has a 2xx status code
func (o *RevokeCDRArrangementByIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke c d r arrangement by Id unauthorized response has a 3xx status code
func (o *RevokeCDRArrangementByIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id unauthorized response has a 4xx status code
func (o *RevokeCDRArrangementByIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke c d r arrangement by Id unauthorized response has a 5xx status code
func (o *RevokeCDRArrangementByIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id unauthorized response a status code equal to that given
func (o *RevokeCDRArrangementByIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the revoke c d r arrangement by Id unauthorized response
func (o *RevokeCDRArrangementByIDUnauthorized) Code() int {
	return 401
}

func (o *RevokeCDRArrangementByIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdUnauthorized %s", 401, payload)
}

func (o *RevokeCDRArrangementByIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdUnauthorized %s", 401, payload)
}

func (o *RevokeCDRArrangementByIDUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeCDRArrangementByIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeCDRArrangementByIDForbidden creates a RevokeCDRArrangementByIDForbidden with default headers values
func NewRevokeCDRArrangementByIDForbidden() *RevokeCDRArrangementByIDForbidden {
	return &RevokeCDRArrangementByIDForbidden{}
}

/*
RevokeCDRArrangementByIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RevokeCDRArrangementByIDForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke c d r arrangement by Id forbidden response has a 2xx status code
func (o *RevokeCDRArrangementByIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke c d r arrangement by Id forbidden response has a 3xx status code
func (o *RevokeCDRArrangementByIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id forbidden response has a 4xx status code
func (o *RevokeCDRArrangementByIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke c d r arrangement by Id forbidden response has a 5xx status code
func (o *RevokeCDRArrangementByIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id forbidden response a status code equal to that given
func (o *RevokeCDRArrangementByIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the revoke c d r arrangement by Id forbidden response
func (o *RevokeCDRArrangementByIDForbidden) Code() int {
	return 403
}

func (o *RevokeCDRArrangementByIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdForbidden %s", 403, payload)
}

func (o *RevokeCDRArrangementByIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdForbidden %s", 403, payload)
}

func (o *RevokeCDRArrangementByIDForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeCDRArrangementByIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeCDRArrangementByIDNotFound creates a RevokeCDRArrangementByIDNotFound with default headers values
func NewRevokeCDRArrangementByIDNotFound() *RevokeCDRArrangementByIDNotFound {
	return &RevokeCDRArrangementByIDNotFound{}
}

/*
RevokeCDRArrangementByIDNotFound describes a response with status code 404, with default header values.

Not found
*/
type RevokeCDRArrangementByIDNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke c d r arrangement by Id not found response has a 2xx status code
func (o *RevokeCDRArrangementByIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke c d r arrangement by Id not found response has a 3xx status code
func (o *RevokeCDRArrangementByIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id not found response has a 4xx status code
func (o *RevokeCDRArrangementByIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke c d r arrangement by Id not found response has a 5xx status code
func (o *RevokeCDRArrangementByIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id not found response a status code equal to that given
func (o *RevokeCDRArrangementByIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the revoke c d r arrangement by Id not found response
func (o *RevokeCDRArrangementByIDNotFound) Code() int {
	return 404
}

func (o *RevokeCDRArrangementByIDNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdNotFound %s", 404, payload)
}

func (o *RevokeCDRArrangementByIDNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdNotFound %s", 404, payload)
}

func (o *RevokeCDRArrangementByIDNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeCDRArrangementByIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeCDRArrangementByIDUnprocessableEntity creates a RevokeCDRArrangementByIDUnprocessableEntity with default headers values
func NewRevokeCDRArrangementByIDUnprocessableEntity() *RevokeCDRArrangementByIDUnprocessableEntity {
	return &RevokeCDRArrangementByIDUnprocessableEntity{}
}

/*
RevokeCDRArrangementByIDUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type RevokeCDRArrangementByIDUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke c d r arrangement by Id unprocessable entity response has a 2xx status code
func (o *RevokeCDRArrangementByIDUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke c d r arrangement by Id unprocessable entity response has a 3xx status code
func (o *RevokeCDRArrangementByIDUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id unprocessable entity response has a 4xx status code
func (o *RevokeCDRArrangementByIDUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke c d r arrangement by Id unprocessable entity response has a 5xx status code
func (o *RevokeCDRArrangementByIDUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id unprocessable entity response a status code equal to that given
func (o *RevokeCDRArrangementByIDUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the revoke c d r arrangement by Id unprocessable entity response
func (o *RevokeCDRArrangementByIDUnprocessableEntity) Code() int {
	return 422
}

func (o *RevokeCDRArrangementByIDUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdUnprocessableEntity %s", 422, payload)
}

func (o *RevokeCDRArrangementByIDUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdUnprocessableEntity %s", 422, payload)
}

func (o *RevokeCDRArrangementByIDUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeCDRArrangementByIDUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRevokeCDRArrangementByIDTooManyRequests creates a RevokeCDRArrangementByIDTooManyRequests with default headers values
func NewRevokeCDRArrangementByIDTooManyRequests() *RevokeCDRArrangementByIDTooManyRequests {
	return &RevokeCDRArrangementByIDTooManyRequests{}
}

/*
RevokeCDRArrangementByIDTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RevokeCDRArrangementByIDTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this revoke c d r arrangement by Id too many requests response has a 2xx status code
func (o *RevokeCDRArrangementByIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this revoke c d r arrangement by Id too many requests response has a 3xx status code
func (o *RevokeCDRArrangementByIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this revoke c d r arrangement by Id too many requests response has a 4xx status code
func (o *RevokeCDRArrangementByIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this revoke c d r arrangement by Id too many requests response has a 5xx status code
func (o *RevokeCDRArrangementByIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this revoke c d r arrangement by Id too many requests response a status code equal to that given
func (o *RevokeCDRArrangementByIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the revoke c d r arrangement by Id too many requests response
func (o *RevokeCDRArrangementByIDTooManyRequests) Code() int {
	return 429
}

func (o *RevokeCDRArrangementByIDTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdTooManyRequests %s", 429, payload)
}

func (o *RevokeCDRArrangementByIDTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /servers/{wid}/cdr/arrangements/{arrangementID}][%d] revokeCDRArrangementByIdTooManyRequests %s", 429, payload)
}

func (o *RevokeCDRArrangementByIDTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RevokeCDRArrangementByIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
