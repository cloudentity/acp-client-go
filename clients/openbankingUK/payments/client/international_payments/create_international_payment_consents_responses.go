// Code generated by go-swagger; DO NOT EDIT.

package international_payments

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/openbankingUK/payments/models"
)

// CreateInternationalPaymentConsentsReader is a Reader for the CreateInternationalPaymentConsents structure.
type CreateInternationalPaymentConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateInternationalPaymentConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateInternationalPaymentConsentsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateInternationalPaymentConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateInternationalPaymentConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateInternationalPaymentConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateInternationalPaymentConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateInternationalPaymentConsentsMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateInternationalPaymentConsentsNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateInternationalPaymentConsentsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateInternationalPaymentConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateInternationalPaymentConsentsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateInternationalPaymentConsentsCreated creates a CreateInternationalPaymentConsentsCreated with default headers values
func NewCreateInternationalPaymentConsentsCreated() *CreateInternationalPaymentConsentsCreated {
	return &CreateInternationalPaymentConsentsCreated{}
}

/*
CreateInternationalPaymentConsentsCreated describes a response with status code 201, with default header values.

International Payment Consents Created
*/
type CreateInternationalPaymentConsentsCreated struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBWriteInternationalConsentResponse6
}

// IsSuccess returns true when this create international payment consents created response has a 2xx status code
func (o *CreateInternationalPaymentConsentsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create international payment consents created response has a 3xx status code
func (o *CreateInternationalPaymentConsentsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents created response has a 4xx status code
func (o *CreateInternationalPaymentConsentsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international payment consents created response has a 5xx status code
func (o *CreateInternationalPaymentConsentsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents created response a status code equal to that given
func (o *CreateInternationalPaymentConsentsCreated) IsCode(code int) bool {
	return code == 201
}

func (o *CreateInternationalPaymentConsentsCreated) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsCreated  %+v", 201, o.Payload)
}

func (o *CreateInternationalPaymentConsentsCreated) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsCreated  %+v", 201, o.Payload)
}

func (o *CreateInternationalPaymentConsentsCreated) GetPayload() *models.OBWriteInternationalConsentResponse6 {
	return o.Payload
}

func (o *CreateInternationalPaymentConsentsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.OBWriteInternationalConsentResponse6)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalPaymentConsentsBadRequest creates a CreateInternationalPaymentConsentsBadRequest with default headers values
func NewCreateInternationalPaymentConsentsBadRequest() *CreateInternationalPaymentConsentsBadRequest {
	return &CreateInternationalPaymentConsentsBadRequest{}
}

/*
CreateInternationalPaymentConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateInternationalPaymentConsentsBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international payment consents bad request response has a 2xx status code
func (o *CreateInternationalPaymentConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents bad request response has a 3xx status code
func (o *CreateInternationalPaymentConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents bad request response has a 4xx status code
func (o *CreateInternationalPaymentConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents bad request response has a 5xx status code
func (o *CreateInternationalPaymentConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents bad request response a status code equal to that given
func (o *CreateInternationalPaymentConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

func (o *CreateInternationalPaymentConsentsBadRequest) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *CreateInternationalPaymentConsentsBadRequest) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsBadRequest  %+v", 400, o.Payload)
}

func (o *CreateInternationalPaymentConsentsBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalPaymentConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalPaymentConsentsUnauthorized creates a CreateInternationalPaymentConsentsUnauthorized with default headers values
func NewCreateInternationalPaymentConsentsUnauthorized() *CreateInternationalPaymentConsentsUnauthorized {
	return &CreateInternationalPaymentConsentsUnauthorized{}
}

/*
CreateInternationalPaymentConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateInternationalPaymentConsentsUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents unauthorized response has a 2xx status code
func (o *CreateInternationalPaymentConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents unauthorized response has a 3xx status code
func (o *CreateInternationalPaymentConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents unauthorized response has a 4xx status code
func (o *CreateInternationalPaymentConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents unauthorized response has a 5xx status code
func (o *CreateInternationalPaymentConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents unauthorized response a status code equal to that given
func (o *CreateInternationalPaymentConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *CreateInternationalPaymentConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsUnauthorized ", 401)
}

func (o *CreateInternationalPaymentConsentsUnauthorized) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsUnauthorized ", 401)
}

func (o *CreateInternationalPaymentConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalPaymentConsentsForbidden creates a CreateInternationalPaymentConsentsForbidden with default headers values
func NewCreateInternationalPaymentConsentsForbidden() *CreateInternationalPaymentConsentsForbidden {
	return &CreateInternationalPaymentConsentsForbidden{}
}

/*
CreateInternationalPaymentConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateInternationalPaymentConsentsForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international payment consents forbidden response has a 2xx status code
func (o *CreateInternationalPaymentConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents forbidden response has a 3xx status code
func (o *CreateInternationalPaymentConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents forbidden response has a 4xx status code
func (o *CreateInternationalPaymentConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents forbidden response has a 5xx status code
func (o *CreateInternationalPaymentConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents forbidden response a status code equal to that given
func (o *CreateInternationalPaymentConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *CreateInternationalPaymentConsentsForbidden) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsForbidden  %+v", 403, o.Payload)
}

func (o *CreateInternationalPaymentConsentsForbidden) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsForbidden  %+v", 403, o.Payload)
}

func (o *CreateInternationalPaymentConsentsForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalPaymentConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalPaymentConsentsNotFound creates a CreateInternationalPaymentConsentsNotFound with default headers values
func NewCreateInternationalPaymentConsentsNotFound() *CreateInternationalPaymentConsentsNotFound {
	return &CreateInternationalPaymentConsentsNotFound{}
}

/*
CreateInternationalPaymentConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateInternationalPaymentConsentsNotFound struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents not found response has a 2xx status code
func (o *CreateInternationalPaymentConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents not found response has a 3xx status code
func (o *CreateInternationalPaymentConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents not found response has a 4xx status code
func (o *CreateInternationalPaymentConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents not found response has a 5xx status code
func (o *CreateInternationalPaymentConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents not found response a status code equal to that given
func (o *CreateInternationalPaymentConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *CreateInternationalPaymentConsentsNotFound) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsNotFound ", 404)
}

func (o *CreateInternationalPaymentConsentsNotFound) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsNotFound ", 404)
}

func (o *CreateInternationalPaymentConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalPaymentConsentsMethodNotAllowed creates a CreateInternationalPaymentConsentsMethodNotAllowed with default headers values
func NewCreateInternationalPaymentConsentsMethodNotAllowed() *CreateInternationalPaymentConsentsMethodNotAllowed {
	return &CreateInternationalPaymentConsentsMethodNotAllowed{}
}

/*
CreateInternationalPaymentConsentsMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type CreateInternationalPaymentConsentsMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents method not allowed response has a 2xx status code
func (o *CreateInternationalPaymentConsentsMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents method not allowed response has a 3xx status code
func (o *CreateInternationalPaymentConsentsMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents method not allowed response has a 4xx status code
func (o *CreateInternationalPaymentConsentsMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents method not allowed response has a 5xx status code
func (o *CreateInternationalPaymentConsentsMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents method not allowed response a status code equal to that given
func (o *CreateInternationalPaymentConsentsMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

func (o *CreateInternationalPaymentConsentsMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsMethodNotAllowed ", 405)
}

func (o *CreateInternationalPaymentConsentsMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsMethodNotAllowed ", 405)
}

func (o *CreateInternationalPaymentConsentsMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalPaymentConsentsNotAcceptable creates a CreateInternationalPaymentConsentsNotAcceptable with default headers values
func NewCreateInternationalPaymentConsentsNotAcceptable() *CreateInternationalPaymentConsentsNotAcceptable {
	return &CreateInternationalPaymentConsentsNotAcceptable{}
}

/*
CreateInternationalPaymentConsentsNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type CreateInternationalPaymentConsentsNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents not acceptable response has a 2xx status code
func (o *CreateInternationalPaymentConsentsNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents not acceptable response has a 3xx status code
func (o *CreateInternationalPaymentConsentsNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents not acceptable response has a 4xx status code
func (o *CreateInternationalPaymentConsentsNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents not acceptable response has a 5xx status code
func (o *CreateInternationalPaymentConsentsNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents not acceptable response a status code equal to that given
func (o *CreateInternationalPaymentConsentsNotAcceptable) IsCode(code int) bool {
	return code == 406
}

func (o *CreateInternationalPaymentConsentsNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsNotAcceptable ", 406)
}

func (o *CreateInternationalPaymentConsentsNotAcceptable) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsNotAcceptable ", 406)
}

func (o *CreateInternationalPaymentConsentsNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalPaymentConsentsUnsupportedMediaType creates a CreateInternationalPaymentConsentsUnsupportedMediaType with default headers values
func NewCreateInternationalPaymentConsentsUnsupportedMediaType() *CreateInternationalPaymentConsentsUnsupportedMediaType {
	return &CreateInternationalPaymentConsentsUnsupportedMediaType{}
}

/*
CreateInternationalPaymentConsentsUnsupportedMediaType describes a response with status code 415, with default header values.

Unsupported Media Type
*/
type CreateInternationalPaymentConsentsUnsupportedMediaType struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents unsupported media type response has a 2xx status code
func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents unsupported media type response has a 3xx status code
func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents unsupported media type response has a 4xx status code
func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents unsupported media type response has a 5xx status code
func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents unsupported media type response a status code equal to that given
func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsUnsupportedMediaType ", 415)
}

func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsUnsupportedMediaType ", 415)
}

func (o *CreateInternationalPaymentConsentsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalPaymentConsentsTooManyRequests creates a CreateInternationalPaymentConsentsTooManyRequests with default headers values
func NewCreateInternationalPaymentConsentsTooManyRequests() *CreateInternationalPaymentConsentsTooManyRequests {
	return &CreateInternationalPaymentConsentsTooManyRequests{}
}

/*
CreateInternationalPaymentConsentsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateInternationalPaymentConsentsTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international payment consents too many requests response has a 2xx status code
func (o *CreateInternationalPaymentConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents too many requests response has a 3xx status code
func (o *CreateInternationalPaymentConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents too many requests response has a 4xx status code
func (o *CreateInternationalPaymentConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international payment consents too many requests response has a 5xx status code
func (o *CreateInternationalPaymentConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create international payment consents too many requests response a status code equal to that given
func (o *CreateInternationalPaymentConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *CreateInternationalPaymentConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsTooManyRequests ", 429)
}

func (o *CreateInternationalPaymentConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsTooManyRequests ", 429)
}

func (o *CreateInternationalPaymentConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalPaymentConsentsInternalServerError creates a CreateInternationalPaymentConsentsInternalServerError with default headers values
func NewCreateInternationalPaymentConsentsInternalServerError() *CreateInternationalPaymentConsentsInternalServerError {
	return &CreateInternationalPaymentConsentsInternalServerError{}
}

/*
CreateInternationalPaymentConsentsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateInternationalPaymentConsentsInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international payment consents internal server error response has a 2xx status code
func (o *CreateInternationalPaymentConsentsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international payment consents internal server error response has a 3xx status code
func (o *CreateInternationalPaymentConsentsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international payment consents internal server error response has a 4xx status code
func (o *CreateInternationalPaymentConsentsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international payment consents internal server error response has a 5xx status code
func (o *CreateInternationalPaymentConsentsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create international payment consents internal server error response a status code equal to that given
func (o *CreateInternationalPaymentConsentsInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *CreateInternationalPaymentConsentsInternalServerError) Error() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateInternationalPaymentConsentsInternalServerError) String() string {
	return fmt.Sprintf("[POST /international-payment-consents][%d] createInternationalPaymentConsentsInternalServerError  %+v", 500, o.Payload)
}

func (o *CreateInternationalPaymentConsentsInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalPaymentConsentsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
