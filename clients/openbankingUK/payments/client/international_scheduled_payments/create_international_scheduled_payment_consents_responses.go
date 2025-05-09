// Code generated by go-swagger; DO NOT EDIT.

package international_scheduled_payments

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

// CreateInternationalScheduledPaymentConsentsReader is a Reader for the CreateInternationalScheduledPaymentConsents structure.
type CreateInternationalScheduledPaymentConsentsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateInternationalScheduledPaymentConsentsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateInternationalScheduledPaymentConsentsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateInternationalScheduledPaymentConsentsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateInternationalScheduledPaymentConsentsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewCreateInternationalScheduledPaymentConsentsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateInternationalScheduledPaymentConsentsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewCreateInternationalScheduledPaymentConsentsMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewCreateInternationalScheduledPaymentConsentsNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 415:
		result := NewCreateInternationalScheduledPaymentConsentsUnsupportedMediaType()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewCreateInternationalScheduledPaymentConsentsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateInternationalScheduledPaymentConsentsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /international-scheduled-payment-consents] CreateInternationalScheduledPaymentConsents", response, response.Code())
	}
}

// NewCreateInternationalScheduledPaymentConsentsCreated creates a CreateInternationalScheduledPaymentConsentsCreated with default headers values
func NewCreateInternationalScheduledPaymentConsentsCreated() *CreateInternationalScheduledPaymentConsentsCreated {
	return &CreateInternationalScheduledPaymentConsentsCreated{}
}

/*
CreateInternationalScheduledPaymentConsentsCreated describes a response with status code 201, with default header values.

International Scheduled Payment Consents Created
*/
type CreateInternationalScheduledPaymentConsentsCreated struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBWriteInternationalScheduledConsentResponse6
}

// IsSuccess returns true when this create international scheduled payment consents created response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create international scheduled payment consents created response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents created response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international scheduled payment consents created response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents created response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the create international scheduled payment consents created response
func (o *CreateInternationalScheduledPaymentConsentsCreated) Code() int {
	return 201
}

func (o *CreateInternationalScheduledPaymentConsentsCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsCreated %s", 201, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsCreated %s", 201, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsCreated) GetPayload() *models.OBWriteInternationalScheduledConsentResponse6 {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.OBWriteInternationalScheduledConsentResponse6)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsBadRequest creates a CreateInternationalScheduledPaymentConsentsBadRequest with default headers values
func NewCreateInternationalScheduledPaymentConsentsBadRequest() *CreateInternationalScheduledPaymentConsentsBadRequest {
	return &CreateInternationalScheduledPaymentConsentsBadRequest{}
}

/*
CreateInternationalScheduledPaymentConsentsBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type CreateInternationalScheduledPaymentConsentsBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international scheduled payment consents bad request response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents bad request response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents bad request response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents bad request response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents bad request response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the create international scheduled payment consents bad request response
func (o *CreateInternationalScheduledPaymentConsentsBadRequest) Code() int {
	return 400
}

func (o *CreateInternationalScheduledPaymentConsentsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsBadRequest %s", 400, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsBadRequest %s", 400, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalScheduledPaymentConsentsUnauthorized creates a CreateInternationalScheduledPaymentConsentsUnauthorized with default headers values
func NewCreateInternationalScheduledPaymentConsentsUnauthorized() *CreateInternationalScheduledPaymentConsentsUnauthorized {
	return &CreateInternationalScheduledPaymentConsentsUnauthorized{}
}

/*
CreateInternationalScheduledPaymentConsentsUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type CreateInternationalScheduledPaymentConsentsUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents unauthorized response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents unauthorized response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents unauthorized response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents unauthorized response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents unauthorized response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the create international scheduled payment consents unauthorized response
func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) Code() int {
	return 401
}

func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsUnauthorized", 401)
}

func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsUnauthorized", 401)
}

func (o *CreateInternationalScheduledPaymentConsentsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsForbidden creates a CreateInternationalScheduledPaymentConsentsForbidden with default headers values
func NewCreateInternationalScheduledPaymentConsentsForbidden() *CreateInternationalScheduledPaymentConsentsForbidden {
	return &CreateInternationalScheduledPaymentConsentsForbidden{}
}

/*
CreateInternationalScheduledPaymentConsentsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type CreateInternationalScheduledPaymentConsentsForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international scheduled payment consents forbidden response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents forbidden response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents forbidden response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents forbidden response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents forbidden response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the create international scheduled payment consents forbidden response
func (o *CreateInternationalScheduledPaymentConsentsForbidden) Code() int {
	return 403
}

func (o *CreateInternationalScheduledPaymentConsentsForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsForbidden %s", 403, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsForbidden %s", 403, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalScheduledPaymentConsentsNotFound creates a CreateInternationalScheduledPaymentConsentsNotFound with default headers values
func NewCreateInternationalScheduledPaymentConsentsNotFound() *CreateInternationalScheduledPaymentConsentsNotFound {
	return &CreateInternationalScheduledPaymentConsentsNotFound{}
}

/*
CreateInternationalScheduledPaymentConsentsNotFound describes a response with status code 404, with default header values.

Not found
*/
type CreateInternationalScheduledPaymentConsentsNotFound struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents not found response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents not found response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents not found response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents not found response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents not found response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the create international scheduled payment consents not found response
func (o *CreateInternationalScheduledPaymentConsentsNotFound) Code() int {
	return 404
}

func (o *CreateInternationalScheduledPaymentConsentsNotFound) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsNotFound", 404)
}

func (o *CreateInternationalScheduledPaymentConsentsNotFound) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsNotFound", 404)
}

func (o *CreateInternationalScheduledPaymentConsentsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsMethodNotAllowed creates a CreateInternationalScheduledPaymentConsentsMethodNotAllowed with default headers values
func NewCreateInternationalScheduledPaymentConsentsMethodNotAllowed() *CreateInternationalScheduledPaymentConsentsMethodNotAllowed {
	return &CreateInternationalScheduledPaymentConsentsMethodNotAllowed{}
}

/*
CreateInternationalScheduledPaymentConsentsMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type CreateInternationalScheduledPaymentConsentsMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents method not allowed response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents method not allowed response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents method not allowed response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents method not allowed response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents method not allowed response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the create international scheduled payment consents method not allowed response
func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) Code() int {
	return 405
}

func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsMethodNotAllowed", 405)
}

func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsMethodNotAllowed", 405)
}

func (o *CreateInternationalScheduledPaymentConsentsMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsNotAcceptable creates a CreateInternationalScheduledPaymentConsentsNotAcceptable with default headers values
func NewCreateInternationalScheduledPaymentConsentsNotAcceptable() *CreateInternationalScheduledPaymentConsentsNotAcceptable {
	return &CreateInternationalScheduledPaymentConsentsNotAcceptable{}
}

/*
CreateInternationalScheduledPaymentConsentsNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type CreateInternationalScheduledPaymentConsentsNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents not acceptable response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents not acceptable response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents not acceptable response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents not acceptable response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents not acceptable response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the create international scheduled payment consents not acceptable response
func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) Code() int {
	return 406
}

func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsNotAcceptable", 406)
}

func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsNotAcceptable", 406)
}

func (o *CreateInternationalScheduledPaymentConsentsNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsUnsupportedMediaType creates a CreateInternationalScheduledPaymentConsentsUnsupportedMediaType with default headers values
func NewCreateInternationalScheduledPaymentConsentsUnsupportedMediaType() *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType {
	return &CreateInternationalScheduledPaymentConsentsUnsupportedMediaType{}
}

/*
CreateInternationalScheduledPaymentConsentsUnsupportedMediaType describes a response with status code 415, with default header values.

Unsupported Media Type
*/
type CreateInternationalScheduledPaymentConsentsUnsupportedMediaType struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents unsupported media type response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents unsupported media type response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents unsupported media type response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents unsupported media type response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents unsupported media type response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) IsCode(code int) bool {
	return code == 415
}

// Code gets the status code for the create international scheduled payment consents unsupported media type response
func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) Code() int {
	return 415
}

func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsUnsupportedMediaType", 415)
}

func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsUnsupportedMediaType", 415)
}

func (o *CreateInternationalScheduledPaymentConsentsUnsupportedMediaType) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewCreateInternationalScheduledPaymentConsentsTooManyRequests creates a CreateInternationalScheduledPaymentConsentsTooManyRequests with default headers values
func NewCreateInternationalScheduledPaymentConsentsTooManyRequests() *CreateInternationalScheduledPaymentConsentsTooManyRequests {
	return &CreateInternationalScheduledPaymentConsentsTooManyRequests{}
}

/*
CreateInternationalScheduledPaymentConsentsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type CreateInternationalScheduledPaymentConsentsTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this create international scheduled payment consents too many requests response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents too many requests response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents too many requests response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this create international scheduled payment consents too many requests response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this create international scheduled payment consents too many requests response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the create international scheduled payment consents too many requests response
func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) Code() int {
	return 429
}

func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsTooManyRequests", 429)
}

func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) String() string {
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsTooManyRequests", 429)
}

func (o *CreateInternationalScheduledPaymentConsentsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCreateInternationalScheduledPaymentConsentsInternalServerError creates a CreateInternationalScheduledPaymentConsentsInternalServerError with default headers values
func NewCreateInternationalScheduledPaymentConsentsInternalServerError() *CreateInternationalScheduledPaymentConsentsInternalServerError {
	return &CreateInternationalScheduledPaymentConsentsInternalServerError{}
}

/*
CreateInternationalScheduledPaymentConsentsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type CreateInternationalScheduledPaymentConsentsInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this create international scheduled payment consents internal server error response has a 2xx status code
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this create international scheduled payment consents internal server error response has a 3xx status code
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create international scheduled payment consents internal server error response has a 4xx status code
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this create international scheduled payment consents internal server error response has a 5xx status code
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this create international scheduled payment consents internal server error response a status code equal to that given
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the create international scheduled payment consents internal server error response
func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) Code() int {
	return 500
}

func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsInternalServerError %s", 500, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /international-scheduled-payment-consents][%d] createInternationalScheduledPaymentConsentsInternalServerError %s", 500, payload)
}

func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *CreateInternationalScheduledPaymentConsentsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
