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

// DeleteDataAccessConsentDeprecatedReader is a Reader for the DeleteDataAccessConsentDeprecated structure.
type DeleteDataAccessConsentDeprecatedReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteDataAccessConsentDeprecatedReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteDataAccessConsentDeprecatedNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteDataAccessConsentDeprecatedBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteDataAccessConsentDeprecatedUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteDataAccessConsentDeprecatedForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewDeleteDataAccessConsentDeprecatedMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewDeleteDataAccessConsentDeprecatedNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewDeleteDataAccessConsentDeprecatedUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewDeleteDataAccessConsentDeprecatedUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteDataAccessConsentDeprecatedTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteDataAccessConsentDeprecatedInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteDataAccessConsentDeprecatedNoContent creates a DeleteDataAccessConsentDeprecatedNoContent with default headers values
func NewDeleteDataAccessConsentDeprecatedNoContent() *DeleteDataAccessConsentDeprecatedNoContent {
	return &DeleteDataAccessConsentDeprecatedNoContent{}
}

/*
DeleteDataAccessConsentDeprecatedNoContent describes a response with status code 204, with default header values.

Customer data access consent
*/
type DeleteDataAccessConsentDeprecatedNoContent struct {
	Payload *models.BrazilCustomerDataAccessConsentResponse
}

// IsSuccess returns true when this delete data access consent deprecated no content response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete data access consent deprecated no content response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated no content response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete data access consent deprecated no content response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated no content response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete data access consent deprecated no content response
func (o *DeleteDataAccessConsentDeprecatedNoContent) Code() int {
	return 204
}

func (o *DeleteDataAccessConsentDeprecatedNoContent) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedNoContent  %+v", 204, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedNoContent) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedNoContent  %+v", 204, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedNoContent) GetPayload() *models.BrazilCustomerDataAccessConsentResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BrazilCustomerDataAccessConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedBadRequest creates a DeleteDataAccessConsentDeprecatedBadRequest with default headers values
func NewDeleteDataAccessConsentDeprecatedBadRequest() *DeleteDataAccessConsentDeprecatedBadRequest {
	return &DeleteDataAccessConsentDeprecatedBadRequest{}
}

/*
DeleteDataAccessConsentDeprecatedBadRequest describes a response with status code 400, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedBadRequest struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated bad request response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated bad request response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated bad request response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated bad request response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated bad request response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete data access consent deprecated bad request response
func (o *DeleteDataAccessConsentDeprecatedBadRequest) Code() int {
	return 400
}

func (o *DeleteDataAccessConsentDeprecatedBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedBadRequest) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedBadRequest) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedUnauthorized creates a DeleteDataAccessConsentDeprecatedUnauthorized with default headers values
func NewDeleteDataAccessConsentDeprecatedUnauthorized() *DeleteDataAccessConsentDeprecatedUnauthorized {
	return &DeleteDataAccessConsentDeprecatedUnauthorized{}
}

/*
DeleteDataAccessConsentDeprecatedUnauthorized describes a response with status code 401, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedUnauthorized struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated unauthorized response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated unauthorized response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated unauthorized response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated unauthorized response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated unauthorized response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete data access consent deprecated unauthorized response
func (o *DeleteDataAccessConsentDeprecatedUnauthorized) Code() int {
	return 401
}

func (o *DeleteDataAccessConsentDeprecatedUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnauthorized) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedForbidden creates a DeleteDataAccessConsentDeprecatedForbidden with default headers values
func NewDeleteDataAccessConsentDeprecatedForbidden() *DeleteDataAccessConsentDeprecatedForbidden {
	return &DeleteDataAccessConsentDeprecatedForbidden{}
}

/*
DeleteDataAccessConsentDeprecatedForbidden describes a response with status code 403, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedForbidden struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated forbidden response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated forbidden response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated forbidden response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated forbidden response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated forbidden response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete data access consent deprecated forbidden response
func (o *DeleteDataAccessConsentDeprecatedForbidden) Code() int {
	return 403
}

func (o *DeleteDataAccessConsentDeprecatedForbidden) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedForbidden  %+v", 403, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedForbidden) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedForbidden  %+v", 403, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedForbidden) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedMethodNotAllowed creates a DeleteDataAccessConsentDeprecatedMethodNotAllowed with default headers values
func NewDeleteDataAccessConsentDeprecatedMethodNotAllowed() *DeleteDataAccessConsentDeprecatedMethodNotAllowed {
	return &DeleteDataAccessConsentDeprecatedMethodNotAllowed{}
}

/*
DeleteDataAccessConsentDeprecatedMethodNotAllowed describes a response with status code 405, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedMethodNotAllowed struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated method not allowed response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated method not allowed response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated method not allowed response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated method not allowed response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated method not allowed response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the delete data access consent deprecated method not allowed response
func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) Code() int {
	return 405
}

func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedMethodNotAllowed  %+v", 405, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedNotAcceptable creates a DeleteDataAccessConsentDeprecatedNotAcceptable with default headers values
func NewDeleteDataAccessConsentDeprecatedNotAcceptable() *DeleteDataAccessConsentDeprecatedNotAcceptable {
	return &DeleteDataAccessConsentDeprecatedNotAcceptable{}
}

/*
DeleteDataAccessConsentDeprecatedNotAcceptable describes a response with status code 406, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedNotAcceptable struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated not acceptable response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated not acceptable response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated not acceptable response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated not acceptable response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated not acceptable response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the delete data access consent deprecated not acceptable response
func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) Code() int {
	return 406
}

func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedNotAcceptable  %+v", 406, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedNotAcceptable  %+v", 406, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedUnsupportedMediaType creates a DeleteDataAccessConsentDeprecatedUnsupportedMediaType with default headers values
func NewDeleteDataAccessConsentDeprecatedUnsupportedMediaType() *DeleteDataAccessConsentDeprecatedUnsupportedMediaType {
	return &DeleteDataAccessConsentDeprecatedUnsupportedMediaType{}
}

/*
DeleteDataAccessConsentDeprecatedUnsupportedMediaType describes a response with status code 415, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedUnsupportedMediaType struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated unsupported media type response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated unsupported media type response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated unsupported media type response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated unsupported media type response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated unsupported media type response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the delete data access consent deprecated unsupported media type response
func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) Code() int {
	return 415
}

func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnsupportedMediaType  %+v", 415, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedUnprocessableEntity creates a DeleteDataAccessConsentDeprecatedUnprocessableEntity with default headers values
func NewDeleteDataAccessConsentDeprecatedUnprocessableEntity() *DeleteDataAccessConsentDeprecatedUnprocessableEntity {
	return &DeleteDataAccessConsentDeprecatedUnprocessableEntity{}
}

/*
DeleteDataAccessConsentDeprecatedUnprocessableEntity describes a response with status code 422, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedUnprocessableEntity struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated unprocessable entity response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated unprocessable entity response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated unprocessable entity response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated unprocessable entity response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated unprocessable entity response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the delete data access consent deprecated unprocessable entity response
func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) Code() int {
	return 422
}

func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedTooManyRequests creates a DeleteDataAccessConsentDeprecatedTooManyRequests with default headers values
func NewDeleteDataAccessConsentDeprecatedTooManyRequests() *DeleteDataAccessConsentDeprecatedTooManyRequests {
	return &DeleteDataAccessConsentDeprecatedTooManyRequests{}
}

/*
DeleteDataAccessConsentDeprecatedTooManyRequests describes a response with status code 429, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedTooManyRequests struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated too many requests response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated too many requests response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated too many requests response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete data access consent deprecated too many requests response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete data access consent deprecated too many requests response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete data access consent deprecated too many requests response
func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) Code() int {
	return 429
}

func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedTooManyRequests  %+v", 429, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteDataAccessConsentDeprecatedInternalServerError creates a DeleteDataAccessConsentDeprecatedInternalServerError with default headers values
func NewDeleteDataAccessConsentDeprecatedInternalServerError() *DeleteDataAccessConsentDeprecatedInternalServerError {
	return &DeleteDataAccessConsentDeprecatedInternalServerError{}
}

/*
DeleteDataAccessConsentDeprecatedInternalServerError describes a response with status code 500, with default header values.

Error
*/
type DeleteDataAccessConsentDeprecatedInternalServerError struct {
	Payload *models.OBBRErrorResponse
}

// IsSuccess returns true when this delete data access consent deprecated internal server error response has a 2xx status code
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete data access consent deprecated internal server error response has a 3xx status code
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete data access consent deprecated internal server error response has a 4xx status code
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete data access consent deprecated internal server error response has a 5xx status code
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete data access consent deprecated internal server error response a status code equal to that given
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete data access consent deprecated internal server error response
func (o *DeleteDataAccessConsentDeprecatedInternalServerError) Code() int {
	return 500
}

func (o *DeleteDataAccessConsentDeprecatedInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /open-banking-brasil/open-banking/consents/v1/consents/{consentID}][%d] deleteDataAccessConsentDeprecatedInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteDataAccessConsentDeprecatedInternalServerError) GetPayload() *models.OBBRErrorResponse {
	return o.Payload
}

func (o *DeleteDataAccessConsentDeprecatedInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OBBRErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
