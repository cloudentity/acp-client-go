// Code generated by go-swagger; DO NOT EDIT.

package file_payments

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/openbankingUK/payments/models"
)

// CreateFilePaymentConsentsReader is a Reader for the CreateFilePaymentConsents structure.
type CreateFilePaymentConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateFilePaymentConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateFilePaymentConsentsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateFilePaymentConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateFilePaymentConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateFilePaymentConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateFilePaymentConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateFilePaymentConsentsMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateFilePaymentConsentsNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateFilePaymentConsentsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateFilePaymentConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateFilePaymentConsentsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /file-payment-consents] CreateFilePaymentConsents", response, response.Code())
	}
}

// NewCreateFilePaymentConsentsCreated creates a CreateFilePaymentConsentsCreated with default headers values
func NewCreateFilePaymentConsentsCreated() *CreateFilePaymentConsentsCreated {
	return &CreateFilePaymentConsentsCreated{}
}

/*
CreateFilePaymentConsentsCreated describes a response with status code 201, with default header values.

File Payment Consents Created
*/
type CreateFilePaymentConsentsCreated struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBWriteFileConsentResponse4
}

// IsSuccess returns true when this create file payment consents created response has a 2xx status code
func (o *CreateFilePaymentConsentsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create file payment consents created response has a 3xx status code
func (o *CreateFilePaymentConsentsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents created response has a 4xx status code
func (o *CreateFilePaymentConsentsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create file payment consents created response has a 5xx status code
func (o *CreateFilePaymentConsentsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents created response a status code equal to that given
func (o *CreateFilePaymentConsentsCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create file payment consents created response
func (o *CreateFilePaymentConsentsCreated) Code() int {
	return 201
}

func (o *CreateFilePaymentConsentsCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsCreated %s", 201, payload)
}

func (o *CreateFilePaymentConsentsCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsCreated %s", 201, payload)
}

func (o *CreateFilePaymentConsentsCreated) GetPayload() *models.OBWriteFileConsentResponse4 {
	return o.Payload
}

func (o *CreateFilePaymentConsentsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	// hydrates response header x-jws-signature
	hdrXJwsSignature := response.GetHeader("x-jws-signature")

	if hdrXJwsSignature != "" {
		o.XJwsSignature = hdrXJwsSignature
	}

	o.Payload = new(models.OBWriteFileConsentResponse4)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentsBadRequest creates a CreateFilePaymentConsentsBadRequest with default headers values
func NewCreateFilePaymentConsentsBadRequest() *CreateFilePaymentConsentsBadRequest {
	return &CreateFilePaymentConsentsBadRequest{}
}

/*
CreateFilePaymentConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateFilePaymentConsentsBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create file payment consents bad request response has a 2xx status code
func (o *CreateFilePaymentConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents bad request response has a 3xx status code
func (o *CreateFilePaymentConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents bad request response has a 4xx status code
func (o *CreateFilePaymentConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents bad request response has a 5xx status code
func (o *CreateFilePaymentConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents bad request response a status code equal to that given
func (o *CreateFilePaymentConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create file payment consents bad request response
func (o *CreateFilePaymentConsentsBadRequest) Code() int {
	return 400
}

func (o *CreateFilePaymentConsentsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsBadRequest %s", 400, payload)
}

func (o *CreateFilePaymentConsentsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsBadRequest %s", 400, payload)
}

func (o *CreateFilePaymentConsentsBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateFilePaymentConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	// hydrates response header x-jws-signature
	hdrXJwsSignature := response.GetHeader("x-jws-signature")

	if hdrXJwsSignature != "" {
		o.XJwsSignature = hdrXJwsSignature
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentsUnauthorized creates a CreateFilePaymentConsentsUnauthorized with default headers values
func NewCreateFilePaymentConsentsUnauthorized() *CreateFilePaymentConsentsUnauthorized {
	return &CreateFilePaymentConsentsUnauthorized{}
}

/*
CreateFilePaymentConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateFilePaymentConsentsUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents unauthorized response has a 2xx status code
func (o *CreateFilePaymentConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents unauthorized response has a 3xx status code
func (o *CreateFilePaymentConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents unauthorized response has a 4xx status code
func (o *CreateFilePaymentConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents unauthorized response has a 5xx status code
func (o *CreateFilePaymentConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents unauthorized response a status code equal to that given
func (o *CreateFilePaymentConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create file payment consents unauthorized response
func (o *CreateFilePaymentConsentsUnauthorized) Code() int {
	return 401
}

func (o *CreateFilePaymentConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsUnauthorized", 401)
}

func (o *CreateFilePaymentConsentsUnauthorized) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsUnauthorized", 401)
}

func (o *CreateFilePaymentConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsForbidden creates a CreateFilePaymentConsentsForbidden with default headers values
func NewCreateFilePaymentConsentsForbidden() *CreateFilePaymentConsentsForbidden {
	return &CreateFilePaymentConsentsForbidden{}
}

/*
CreateFilePaymentConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateFilePaymentConsentsForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create file payment consents forbidden response has a 2xx status code
func (o *CreateFilePaymentConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents forbidden response has a 3xx status code
func (o *CreateFilePaymentConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents forbidden response has a 4xx status code
func (o *CreateFilePaymentConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents forbidden response has a 5xx status code
func (o *CreateFilePaymentConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents forbidden response a status code equal to that given
func (o *CreateFilePaymentConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create file payment consents forbidden response
func (o *CreateFilePaymentConsentsForbidden) Code() int {
	return 403
}

func (o *CreateFilePaymentConsentsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsForbidden %s", 403, payload)
}

func (o *CreateFilePaymentConsentsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsForbidden %s", 403, payload)
}

func (o *CreateFilePaymentConsentsForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateFilePaymentConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	// hydrates response header x-jws-signature
	hdrXJwsSignature := response.GetHeader("x-jws-signature")

	if hdrXJwsSignature != "" {
		o.XJwsSignature = hdrXJwsSignature
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateFilePaymentConsentsNotFound creates a CreateFilePaymentConsentsNotFound with default headers values
func NewCreateFilePaymentConsentsNotFound() *CreateFilePaymentConsentsNotFound {
	return &CreateFilePaymentConsentsNotFound{}
}

/*
CreateFilePaymentConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateFilePaymentConsentsNotFound struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents not found response has a 2xx status code
func (o *CreateFilePaymentConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents not found response has a 3xx status code
func (o *CreateFilePaymentConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents not found response has a 4xx status code
func (o *CreateFilePaymentConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents not found response has a 5xx status code
func (o *CreateFilePaymentConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents not found response a status code equal to that given
func (o *CreateFilePaymentConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create file payment consents not found response
func (o *CreateFilePaymentConsentsNotFound) Code() int {
	return 404
}

func (o *CreateFilePaymentConsentsNotFound) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsNotFound", 404)
}

func (o *CreateFilePaymentConsentsNotFound) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsNotFound", 404)
}

func (o *CreateFilePaymentConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsMethodNotAllowed creates a CreateFilePaymentConsentsMethodNotAllowed with default headers values
func NewCreateFilePaymentConsentsMethodNotAllowed() *CreateFilePaymentConsentsMethodNotAllowed {
	return &CreateFilePaymentConsentsMethodNotAllowed{}
}

/*
CreateFilePaymentConsentsMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type CreateFilePaymentConsentsMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents method not allowed response has a 2xx status code
func (o *CreateFilePaymentConsentsMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents method not allowed response has a 3xx status code
func (o *CreateFilePaymentConsentsMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents method not allowed response has a 4xx status code
func (o *CreateFilePaymentConsentsMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents method not allowed response has a 5xx status code
func (o *CreateFilePaymentConsentsMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents method not allowed response a status code equal to that given
func (o *CreateFilePaymentConsentsMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create file payment consents method not allowed response
func (o *CreateFilePaymentConsentsMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateFilePaymentConsentsMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsMethodNotAllowed", 405)
}

func (o *CreateFilePaymentConsentsMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsMethodNotAllowed", 405)
}

func (o *CreateFilePaymentConsentsMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsNotAcceptable creates a CreateFilePaymentConsentsNotAcceptable with default headers values
func NewCreateFilePaymentConsentsNotAcceptable() *CreateFilePaymentConsentsNotAcceptable {
	return &CreateFilePaymentConsentsNotAcceptable{}
}

/*
CreateFilePaymentConsentsNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type CreateFilePaymentConsentsNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents not acceptable response has a 2xx status code
func (o *CreateFilePaymentConsentsNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents not acceptable response has a 3xx status code
func (o *CreateFilePaymentConsentsNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents not acceptable response has a 4xx status code
func (o *CreateFilePaymentConsentsNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents not acceptable response has a 5xx status code
func (o *CreateFilePaymentConsentsNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents not acceptable response a status code equal to that given
func (o *CreateFilePaymentConsentsNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create file payment consents not acceptable response
func (o *CreateFilePaymentConsentsNotAcceptable) Code() int {
	return 406
}

func (o *CreateFilePaymentConsentsNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsNotAcceptable", 406)
}

func (o *CreateFilePaymentConsentsNotAcceptable) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsNotAcceptable", 406)
}

func (o *CreateFilePaymentConsentsNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsUnsupportedMediaType creates a CreateFilePaymentConsentsUnsupportedMediaType with default headers values
func NewCreateFilePaymentConsentsUnsupportedMediaType() *CreateFilePaymentConsentsUnsupportedMediaType {
	return &CreateFilePaymentConsentsUnsupportedMediaType{}
}

/*
CreateFilePaymentConsentsUnsupportedMediaType describes a response with status code 415, with default header values.

Unsupported Media Type
*/
type CreateFilePaymentConsentsUnsupportedMediaType struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents unsupported media type response has a 2xx status code
func (o *CreateFilePaymentConsentsUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents unsupported media type response has a 3xx status code
func (o *CreateFilePaymentConsentsUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents unsupported media type response has a 4xx status code
func (o *CreateFilePaymentConsentsUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents unsupported media type response has a 5xx status code
func (o *CreateFilePaymentConsentsUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents unsupported media type response a status code equal to that given
func (o *CreateFilePaymentConsentsUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create file payment consents unsupported media type response
func (o *CreateFilePaymentConsentsUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateFilePaymentConsentsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsUnsupportedMediaType", 415)
}

func (o *CreateFilePaymentConsentsUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsUnsupportedMediaType", 415)
}

func (o *CreateFilePaymentConsentsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsTooManyRequests creates a CreateFilePaymentConsentsTooManyRequests with default headers values
func NewCreateFilePaymentConsentsTooManyRequests() *CreateFilePaymentConsentsTooManyRequests {
	return &CreateFilePaymentConsentsTooManyRequests{}
}

/*
CreateFilePaymentConsentsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateFilePaymentConsentsTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create file payment consents too many requests response has a 2xx status code
func (o *CreateFilePaymentConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents too many requests response has a 3xx status code
func (o *CreateFilePaymentConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents too many requests response has a 4xx status code
func (o *CreateFilePaymentConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create file payment consents too many requests response has a 5xx status code
func (o *CreateFilePaymentConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create file payment consents too many requests response a status code equal to that given
func (o *CreateFilePaymentConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create file payment consents too many requests response
func (o *CreateFilePaymentConsentsTooManyRequests) Code() int {
	return 429
}

func (o *CreateFilePaymentConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsTooManyRequests", 429)
}

func (o *CreateFilePaymentConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsTooManyRequests", 429)
}

func (o *CreateFilePaymentConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Retry-After
	hdrRetryAfter := response.GetHeader("Retry-After")

	if hdrRetryAfter != "" {
		valretryAfter, err := swag.ConvertInt64(hdrRetryAfter)
		if err != nil {
			return errors.InvalidType("Retry-After", "header", "int64", hdrRetryAfter)
		}
		o.RetryAfter = valretryAfter
	}

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateFilePaymentConsentsInternalServerError creates a CreateFilePaymentConsentsInternalServerError with default headers values
func NewCreateFilePaymentConsentsInternalServerError() *CreateFilePaymentConsentsInternalServerError {
	return &CreateFilePaymentConsentsInternalServerError{}
}

/*
CreateFilePaymentConsentsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateFilePaymentConsentsInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create file payment consents internal server error response has a 2xx status code
func (o *CreateFilePaymentConsentsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create file payment consents internal server error response has a 3xx status code
func (o *CreateFilePaymentConsentsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create file payment consents internal server error response has a 4xx status code
func (o *CreateFilePaymentConsentsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create file payment consents internal server error response has a 5xx status code
func (o *CreateFilePaymentConsentsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create file payment consents internal server error response a status code equal to that given
func (o *CreateFilePaymentConsentsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create file payment consents internal server error response
func (o *CreateFilePaymentConsentsInternalServerError) Code() int {
	return 500
}

func (o *CreateFilePaymentConsentsInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsInternalServerError %s", 500, payload)
}

func (o *CreateFilePaymentConsentsInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /file-payment-consents][%d] createFilePaymentConsentsInternalServerError %s", 500, payload)
}

func (o *CreateFilePaymentConsentsInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateFilePaymentConsentsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	// hydrates response header x-jws-signature
	hdrXJwsSignature := response.GetHeader("x-jws-signature")

	if hdrXJwsSignature != "" {
		o.XJwsSignature = hdrXJwsSignature
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
