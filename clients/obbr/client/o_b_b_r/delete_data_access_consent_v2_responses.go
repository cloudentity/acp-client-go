// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// DeleteDataAccessConsentV2Reader is a Reader for the DeleteDataAccessConsentV2 structure.
type DeleteDataAccessConsentV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteDataAccessConsentV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteDataAccessConsentV2NoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteDataAccessConsentV2BadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteDataAccessConsentV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteDataAccessConsentV2Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewDeleteDataAccessConsentV2MethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewDeleteDataAccessConsentV2NotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewDeleteDataAccessConsentV2UnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewDeleteDataAccessConsentV2UnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteDataAccessConsentV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteDataAccessConsentV2InternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteDataAccessConsentV2NoContent creates a DeleteDataAccessConsentV2NoContent with default headers values
func NewDeleteDataAccessConsentV2NoContent() *DeleteDataAccessConsentV2NoContent {
	return &DeleteDataAccessConsentV2NoContent{}
}

/*
DeleteDataAccessConsentV2NoContent describes a response with status code 204, with default header values.

	consent deleted
*/
type DeleteDataAccessConsentV2NoContent struct {
}

// IsSuccess returns true when this delete data access consent v2 no content response has a 2xx status code
func (o *DeleteDataAccessConsentV2NoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete data access consent v2 no content response has a 3xx status code
func (o *DeleteDataAccessConsentV2NoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 no content response has a 4xx status code
func (o *DeleteDataAccessConsentV2NoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete data access consent v2 no content response has a 5xx status code
func (o *DeleteDataAccessConsentV2NoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 no content response a status code equal to that given
func (o *DeleteDataAccessConsentV2NoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete data access consent v2 no content response
func (o *DeleteDataAccessConsentV2NoContent) Code() int {
	return 204
}

func (o *DeleteDataAccessConsentV2NoContent) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2NoContent ", 204)
}

func (o *DeleteDataAccessConsentV2NoContent) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2NoContent ", 204)
}

func (o *DeleteDataAccessConsentV2NoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteDataAccessConsentV2BadRequest creates a DeleteDataAccessConsentV2BadRequest with default headers values
func NewDeleteDataAccessConsentV2BadRequest() *DeleteDataAccessConsentV2BadRequest {
	return &DeleteDataAccessConsentV2BadRequest{}
}

/*
DeleteDataAccessConsentV2BadRequest describes a response with status code 400, with default header values.

Error
*/
type DeleteDataAccessConsentV2BadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 bad request response has a 2xx status code
func (o *DeleteDataAccessConsentV2BadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 bad request response has a 3xx status code
func (o *DeleteDataAccessConsentV2BadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 bad request response has a 4xx status code
func (o *DeleteDataAccessConsentV2BadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 bad request response has a 5xx status code
func (o *DeleteDataAccessConsentV2BadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 bad request response a status code equal to that given
func (o *DeleteDataAccessConsentV2BadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete data access consent v2 bad request response
func (o *DeleteDataAccessConsentV2BadRequest) Code() int {
	return 400
}

func (o *DeleteDataAccessConsentV2BadRequest) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2BadRequest  %+v", 400, o.Payload)
}

func (o *DeleteDataAccessConsentV2BadRequest) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2BadRequest  %+v", 400, o.Payload)
}

func (o *DeleteDataAccessConsentV2BadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2BadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2Unauthorized creates a DeleteDataAccessConsentV2Unauthorized with default headers values
func NewDeleteDataAccessConsentV2Unauthorized() *DeleteDataAccessConsentV2Unauthorized {
	return &DeleteDataAccessConsentV2Unauthorized{}
}

/*
DeleteDataAccessConsentV2Unauthorized describes a response with status code 401, with default header values.

Error
*/
type DeleteDataAccessConsentV2Unauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 unauthorized response has a 2xx status code
func (o *DeleteDataAccessConsentV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 unauthorized response has a 3xx status code
func (o *DeleteDataAccessConsentV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 unauthorized response has a 4xx status code
func (o *DeleteDataAccessConsentV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 unauthorized response has a 5xx status code
func (o *DeleteDataAccessConsentV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 unauthorized response a status code equal to that given
func (o *DeleteDataAccessConsentV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete data access consent v2 unauthorized response
func (o *DeleteDataAccessConsentV2Unauthorized) Code() int {
	return 401
}

func (o *DeleteDataAccessConsentV2Unauthorized) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2Unauthorized  %+v", 401, o.Payload)
}

func (o *DeleteDataAccessConsentV2Unauthorized) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2Unauthorized  %+v", 401, o.Payload)
}

func (o *DeleteDataAccessConsentV2Unauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2Forbidden creates a DeleteDataAccessConsentV2Forbidden with default headers values
func NewDeleteDataAccessConsentV2Forbidden() *DeleteDataAccessConsentV2Forbidden {
	return &DeleteDataAccessConsentV2Forbidden{}
}

/*
DeleteDataAccessConsentV2Forbidden describes a response with status code 403, with default header values.

Error
*/
type DeleteDataAccessConsentV2Forbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 forbidden response has a 2xx status code
func (o *DeleteDataAccessConsentV2Forbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 forbidden response has a 3xx status code
func (o *DeleteDataAccessConsentV2Forbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 forbidden response has a 4xx status code
func (o *DeleteDataAccessConsentV2Forbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 forbidden response has a 5xx status code
func (o *DeleteDataAccessConsentV2Forbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 forbidden response a status code equal to that given
func (o *DeleteDataAccessConsentV2Forbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete data access consent v2 forbidden response
func (o *DeleteDataAccessConsentV2Forbidden) Code() int {
	return 403
}

func (o *DeleteDataAccessConsentV2Forbidden) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2Forbidden  %+v", 403, o.Payload)
}

func (o *DeleteDataAccessConsentV2Forbidden) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2Forbidden  %+v", 403, o.Payload)
}

func (o *DeleteDataAccessConsentV2Forbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2MethodNotAllowed creates a DeleteDataAccessConsentV2MethodNotAllowed with default headers values
func NewDeleteDataAccessConsentV2MethodNotAllowed() *DeleteDataAccessConsentV2MethodNotAllowed {
	return &DeleteDataAccessConsentV2MethodNotAllowed{}
}

/*
DeleteDataAccessConsentV2MethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type DeleteDataAccessConsentV2MethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 method not allowed response has a 2xx status code
func (o *DeleteDataAccessConsentV2MethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 method not allowed response has a 3xx status code
func (o *DeleteDataAccessConsentV2MethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 method not allowed response has a 4xx status code
func (o *DeleteDataAccessConsentV2MethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 method not allowed response has a 5xx status code
func (o *DeleteDataAccessConsentV2MethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 method not allowed response a status code equal to that given
func (o *DeleteDataAccessConsentV2MethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the delete data access consent v2 method not allowed response
func (o *DeleteDataAccessConsentV2MethodNotAllowed) Code() int {
	return 405
}

func (o *DeleteDataAccessConsentV2MethodNotAllowed) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeleteDataAccessConsentV2MethodNotAllowed) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2MethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeleteDataAccessConsentV2MethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2MethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2NotAcceptable creates a DeleteDataAccessConsentV2NotAcceptable with default headers values
func NewDeleteDataAccessConsentV2NotAcceptable() *DeleteDataAccessConsentV2NotAcceptable {
	return &DeleteDataAccessConsentV2NotAcceptable{}
}

/*
DeleteDataAccessConsentV2NotAcceptable describes a response with status code 406, with default header values.

Error
*/
type DeleteDataAccessConsentV2NotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 not acceptable response has a 2xx status code
func (o *DeleteDataAccessConsentV2NotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 not acceptable response has a 3xx status code
func (o *DeleteDataAccessConsentV2NotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 not acceptable response has a 4xx status code
func (o *DeleteDataAccessConsentV2NotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 not acceptable response has a 5xx status code
func (o *DeleteDataAccessConsentV2NotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 not acceptable response a status code equal to that given
func (o *DeleteDataAccessConsentV2NotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the delete data access consent v2 not acceptable response
func (o *DeleteDataAccessConsentV2NotAcceptable) Code() int {
	return 406
}

func (o *DeleteDataAccessConsentV2NotAcceptable) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2NotAcceptable  %+v", 406, o.Payload)
}

func (o *DeleteDataAccessConsentV2NotAcceptable) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2NotAcceptable  %+v", 406, o.Payload)
}

func (o *DeleteDataAccessConsentV2NotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2NotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2UnsupportedMediaType creates a DeleteDataAccessConsentV2UnsupportedMediaType with default headers values
func NewDeleteDataAccessConsentV2UnsupportedMediaType() *DeleteDataAccessConsentV2UnsupportedMediaType {
	return &DeleteDataAccessConsentV2UnsupportedMediaType{}
}

/*
DeleteDataAccessConsentV2UnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type DeleteDataAccessConsentV2UnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 unsupported media type response has a 2xx status code
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 unsupported media type response has a 3xx status code
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 unsupported media type response has a 4xx status code
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 unsupported media type response has a 5xx status code
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 unsupported media type response a status code equal to that given
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the delete data access consent v2 unsupported media type response
func (o *DeleteDataAccessConsentV2UnsupportedMediaType) Code() int {
	return 415
}

func (o *DeleteDataAccessConsentV2UnsupportedMediaType) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *DeleteDataAccessConsentV2UnsupportedMediaType) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2UnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *DeleteDataAccessConsentV2UnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2UnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2UnprocessableEntity creates a DeleteDataAccessConsentV2UnprocessableEntity with default headers values
func NewDeleteDataAccessConsentV2UnprocessableEntity() *DeleteDataAccessConsentV2UnprocessableEntity {
	return &DeleteDataAccessConsentV2UnprocessableEntity{}
}

/*
DeleteDataAccessConsentV2UnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type DeleteDataAccessConsentV2UnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 unprocessable entity response has a 2xx status code
func (o *DeleteDataAccessConsentV2UnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 unprocessable entity response has a 3xx status code
func (o *DeleteDataAccessConsentV2UnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 unprocessable entity response has a 4xx status code
func (o *DeleteDataAccessConsentV2UnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 unprocessable entity response has a 5xx status code
func (o *DeleteDataAccessConsentV2UnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 unprocessable entity response a status code equal to that given
func (o *DeleteDataAccessConsentV2UnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the delete data access consent v2 unprocessable entity response
func (o *DeleteDataAccessConsentV2UnprocessableEntity) Code() int {
	return 422
}

func (o *DeleteDataAccessConsentV2UnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *DeleteDataAccessConsentV2UnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2UnprocessableEntity  %+v", 422, o.Payload)
}

func (o *DeleteDataAccessConsentV2UnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2UnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2TooManyRequests creates a DeleteDataAccessConsentV2TooManyRequests with default headers values
func NewDeleteDataAccessConsentV2TooManyRequests() *DeleteDataAccessConsentV2TooManyRequests {
	return &DeleteDataAccessConsentV2TooManyRequests{}
}

/*
DeleteDataAccessConsentV2TooManyRequests describes a response with status code 429, with default header values.

Error
*/
type DeleteDataAccessConsentV2TooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 too many requests response has a 2xx status code
func (o *DeleteDataAccessConsentV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 too many requests response has a 3xx status code
func (o *DeleteDataAccessConsentV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 too many requests response has a 4xx status code
func (o *DeleteDataAccessConsentV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent v2 too many requests response has a 5xx status code
func (o *DeleteDataAccessConsentV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent v2 too many requests response a status code equal to that given
func (o *DeleteDataAccessConsentV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete data access consent v2 too many requests response
func (o *DeleteDataAccessConsentV2TooManyRequests) Code() int {
	return 429
}

func (o *DeleteDataAccessConsentV2TooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteDataAccessConsentV2TooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteDataAccessConsentV2TooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentV2InternalServerError creates a DeleteDataAccessConsentV2InternalServerError with default headers values
func NewDeleteDataAccessConsentV2InternalServerError() *DeleteDataAccessConsentV2InternalServerError {
	return &DeleteDataAccessConsentV2InternalServerError{}
}

/*
DeleteDataAccessConsentV2InternalServerError describes a response with status code 500, with default header values.

Error
*/
type DeleteDataAccessConsentV2InternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent v2 internal server error response has a 2xx status code
func (o *DeleteDataAccessConsentV2InternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent v2 internal server error response has a 3xx status code
func (o *DeleteDataAccessConsentV2InternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent v2 internal server error response has a 4xx status code
func (o *DeleteDataAccessConsentV2InternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete data access consent v2 internal server error response has a 5xx status code
func (o *DeleteDataAccessConsentV2InternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete data access consent v2 internal server error response a status code equal to that given
func (o *DeleteDataAccessConsentV2InternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete data access consent v2 internal server error response
func (o *DeleteDataAccessConsentV2InternalServerError) Code() int {
	return 500
}

func (o *DeleteDataAccessConsentV2InternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2InternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteDataAccessConsentV2InternalServerError) String() string {
	return fmt.Sprintf("[DELETE /open-banking/consents/v2/consents/{consentID}][%d] deleteDataAccessConsentV2InternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteDataAccessConsentV2InternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentV2InternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
