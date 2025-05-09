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

// GetFilePaymentConsentsConsentIDReader is a Reader for the GetFilePaymentConsentsConsentID structure.
type GetFilePaymentConsentsConsentIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetFilePaymentConsentsConsentIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetFilePaymentConsentsConsentIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetFilePaymentConsentsConsentIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetFilePaymentConsentsConsentIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetFilePaymentConsentsConsentIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetFilePaymentConsentsConsentIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetFilePaymentConsentsConsentIDMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetFilePaymentConsentsConsentIDNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetFilePaymentConsentsConsentIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetFilePaymentConsentsConsentIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /file-payment-consents/{ConsentId}] GetFilePaymentConsentsConsentId", response, response.Code())
	}
}

// NewGetFilePaymentConsentsConsentIDOK creates a GetFilePaymentConsentsConsentIDOK with default headers values
func NewGetFilePaymentConsentsConsentIDOK() *GetFilePaymentConsentsConsentIDOK {
	return &GetFilePaymentConsentsConsentIDOK{}
}

/*
GetFilePaymentConsentsConsentIDOK describes a response with status code 200, with default header values.

File Payment Consents Read
*/
type GetFilePaymentConsentsConsentIDOK struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBWriteFileConsentResponse4
}

// IsSuccess returns true when this get file payment consents consent Id o k response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get file payment consents consent Id o k response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id o k response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file payment consents consent Id o k response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id o k response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get file payment consents consent Id o k response
func (o *GetFilePaymentConsentsConsentIDOK) Code() int {
	return 200
}

func (o *GetFilePaymentConsentsConsentIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdOK %s", 200, payload)
}

func (o *GetFilePaymentConsentsConsentIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdOK %s", 200, payload)
}

func (o *GetFilePaymentConsentsConsentIDOK) GetPayload() *models.OBWriteFileConsentResponse4 {
	return o.Payload
}

func (o *GetFilePaymentConsentsConsentIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetFilePaymentConsentsConsentIDBadRequest creates a GetFilePaymentConsentsConsentIDBadRequest with default headers values
func NewGetFilePaymentConsentsConsentIDBadRequest() *GetFilePaymentConsentsConsentIDBadRequest {
	return &GetFilePaymentConsentsConsentIDBadRequest{}
}

/*
GetFilePaymentConsentsConsentIDBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetFilePaymentConsentsConsentIDBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get file payment consents consent Id bad request response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id bad request response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id bad request response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id bad request response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id bad request response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get file payment consents consent Id bad request response
func (o *GetFilePaymentConsentsConsentIDBadRequest) Code() int {
	return 400
}

func (o *GetFilePaymentConsentsConsentIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetFilePaymentConsentsConsentIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetFilePaymentConsentsConsentIDBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetFilePaymentConsentsConsentIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetFilePaymentConsentsConsentIDUnauthorized creates a GetFilePaymentConsentsConsentIDUnauthorized with default headers values
func NewGetFilePaymentConsentsConsentIDUnauthorized() *GetFilePaymentConsentsConsentIDUnauthorized {
	return &GetFilePaymentConsentsConsentIDUnauthorized{}
}

/*
GetFilePaymentConsentsConsentIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetFilePaymentConsentsConsentIDUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get file payment consents consent Id unauthorized response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id unauthorized response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id unauthorized response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id unauthorized response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id unauthorized response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get file payment consents consent Id unauthorized response
func (o *GetFilePaymentConsentsConsentIDUnauthorized) Code() int {
	return 401
}

func (o *GetFilePaymentConsentsConsentIDUnauthorized) Error() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdUnauthorized", 401)
}

func (o *GetFilePaymentConsentsConsentIDUnauthorized) String() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdUnauthorized", 401)
}

func (o *GetFilePaymentConsentsConsentIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetFilePaymentConsentsConsentIDForbidden creates a GetFilePaymentConsentsConsentIDForbidden with default headers values
func NewGetFilePaymentConsentsConsentIDForbidden() *GetFilePaymentConsentsConsentIDForbidden {
	return &GetFilePaymentConsentsConsentIDForbidden{}
}

/*
GetFilePaymentConsentsConsentIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetFilePaymentConsentsConsentIDForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get file payment consents consent Id forbidden response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id forbidden response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id forbidden response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id forbidden response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id forbidden response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get file payment consents consent Id forbidden response
func (o *GetFilePaymentConsentsConsentIDForbidden) Code() int {
	return 403
}

func (o *GetFilePaymentConsentsConsentIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetFilePaymentConsentsConsentIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetFilePaymentConsentsConsentIDForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetFilePaymentConsentsConsentIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetFilePaymentConsentsConsentIDNotFound creates a GetFilePaymentConsentsConsentIDNotFound with default headers values
func NewGetFilePaymentConsentsConsentIDNotFound() *GetFilePaymentConsentsConsentIDNotFound {
	return &GetFilePaymentConsentsConsentIDNotFound{}
}

/*
GetFilePaymentConsentsConsentIDNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetFilePaymentConsentsConsentIDNotFound struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get file payment consents consent Id not found response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id not found response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id not found response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id not found response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id not found response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get file payment consents consent Id not found response
func (o *GetFilePaymentConsentsConsentIDNotFound) Code() int {
	return 404
}

func (o *GetFilePaymentConsentsConsentIDNotFound) Error() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdNotFound", 404)
}

func (o *GetFilePaymentConsentsConsentIDNotFound) String() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdNotFound", 404)
}

func (o *GetFilePaymentConsentsConsentIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetFilePaymentConsentsConsentIDMethodNotAllowed creates a GetFilePaymentConsentsConsentIDMethodNotAllowed with default headers values
func NewGetFilePaymentConsentsConsentIDMethodNotAllowed() *GetFilePaymentConsentsConsentIDMethodNotAllowed {
	return &GetFilePaymentConsentsConsentIDMethodNotAllowed{}
}

/*
GetFilePaymentConsentsConsentIDMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type GetFilePaymentConsentsConsentIDMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get file payment consents consent Id method not allowed response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id method not allowed response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id method not allowed response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id method not allowed response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id method not allowed response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get file payment consents consent Id method not allowed response
func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) Code() int {
	return 405
}

func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetFilePaymentConsentsConsentIDMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetFilePaymentConsentsConsentIDNotAcceptable creates a GetFilePaymentConsentsConsentIDNotAcceptable with default headers values
func NewGetFilePaymentConsentsConsentIDNotAcceptable() *GetFilePaymentConsentsConsentIDNotAcceptable {
	return &GetFilePaymentConsentsConsentIDNotAcceptable{}
}

/*
GetFilePaymentConsentsConsentIDNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type GetFilePaymentConsentsConsentIDNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get file payment consents consent Id not acceptable response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id not acceptable response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id not acceptable response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id not acceptable response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id not acceptable response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get file payment consents consent Id not acceptable response
func (o *GetFilePaymentConsentsConsentIDNotAcceptable) Code() int {
	return 406
}

func (o *GetFilePaymentConsentsConsentIDNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdNotAcceptable", 406)
}

func (o *GetFilePaymentConsentsConsentIDNotAcceptable) String() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdNotAcceptable", 406)
}

func (o *GetFilePaymentConsentsConsentIDNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetFilePaymentConsentsConsentIDTooManyRequests creates a GetFilePaymentConsentsConsentIDTooManyRequests with default headers values
func NewGetFilePaymentConsentsConsentIDTooManyRequests() *GetFilePaymentConsentsConsentIDTooManyRequests {
	return &GetFilePaymentConsentsConsentIDTooManyRequests{}
}

/*
GetFilePaymentConsentsConsentIDTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetFilePaymentConsentsConsentIDTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get file payment consents consent Id too many requests response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id too many requests response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id too many requests response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get file payment consents consent Id too many requests response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get file payment consents consent Id too many requests response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get file payment consents consent Id too many requests response
func (o *GetFilePaymentConsentsConsentIDTooManyRequests) Code() int {
	return 429
}

func (o *GetFilePaymentConsentsConsentIDTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdTooManyRequests", 429)
}

func (o *GetFilePaymentConsentsConsentIDTooManyRequests) String() string {
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdTooManyRequests", 429)
}

func (o *GetFilePaymentConsentsConsentIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetFilePaymentConsentsConsentIDInternalServerError creates a GetFilePaymentConsentsConsentIDInternalServerError with default headers values
func NewGetFilePaymentConsentsConsentIDInternalServerError() *GetFilePaymentConsentsConsentIDInternalServerError {
	return &GetFilePaymentConsentsConsentIDInternalServerError{}
}

/*
GetFilePaymentConsentsConsentIDInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetFilePaymentConsentsConsentIDInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get file payment consents consent Id internal server error response has a 2xx status code
func (o *GetFilePaymentConsentsConsentIDInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get file payment consents consent Id internal server error response has a 3xx status code
func (o *GetFilePaymentConsentsConsentIDInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get file payment consents consent Id internal server error response has a 4xx status code
func (o *GetFilePaymentConsentsConsentIDInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get file payment consents consent Id internal server error response has a 5xx status code
func (o *GetFilePaymentConsentsConsentIDInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get file payment consents consent Id internal server error response a status code equal to that given
func (o *GetFilePaymentConsentsConsentIDInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get file payment consents consent Id internal server error response
func (o *GetFilePaymentConsentsConsentIDInternalServerError) Code() int {
	return 500
}

func (o *GetFilePaymentConsentsConsentIDInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetFilePaymentConsentsConsentIDInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /file-payment-consents/{ConsentId}][%d] getFilePaymentConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetFilePaymentConsentsConsentIDInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetFilePaymentConsentsConsentIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
