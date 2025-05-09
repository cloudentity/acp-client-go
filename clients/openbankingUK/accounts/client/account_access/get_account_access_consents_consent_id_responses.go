// Code generated by go-swagger; DO NOT EDIT.

package account_access

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

	"github.com/cloudentity/acp-client-go/clients/openbankingUK/accounts/models"
)

// GetAccountAccessConsentsConsentIDReader is a Reader for the GetAccountAccessConsentsConsentID structure.
type GetAccountAccessConsentsConsentIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAccountAccessConsentsConsentIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAccountAccessConsentsConsentIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAccountAccessConsentsConsentIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAccountAccessConsentsConsentIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetAccountAccessConsentsConsentIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetAccountAccessConsentsConsentIDMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetAccountAccessConsentsConsentIDNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetAccountAccessConsentsConsentIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAccountAccessConsentsConsentIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /account-access-consents/{ConsentId}] GetAccountAccessConsentsConsentId", response, response.Code())
	}
}

// NewGetAccountAccessConsentsConsentIDOK creates a GetAccountAccessConsentsConsentIDOK with default headers values
func NewGetAccountAccessConsentsConsentIDOK() *GetAccountAccessConsentsConsentIDOK {
	return &GetAccountAccessConsentsConsentIDOK{}
}

/*
GetAccountAccessConsentsConsentIDOK describes a response with status code 200, with default header values.

Account Access Consents Read
*/
type GetAccountAccessConsentsConsentIDOK struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBReadConsentResponse1
}

// IsSuccess returns true when this get account access consents consent Id o k response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get account access consents consent Id o k response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id o k response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get account access consents consent Id o k response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id o k response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get account access consents consent Id o k response
func (o *GetAccountAccessConsentsConsentIDOK) Code() int {
	return 200
}

func (o *GetAccountAccessConsentsConsentIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdOK %s", 200, payload)
}

func (o *GetAccountAccessConsentsConsentIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdOK %s", 200, payload)
}

func (o *GetAccountAccessConsentsConsentIDOK) GetPayload() *models.OBReadConsentResponse1 {
	return o.Payload
}

func (o *GetAccountAccessConsentsConsentIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBReadConsentResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDBadRequest creates a GetAccountAccessConsentsConsentIDBadRequest with default headers values
func NewGetAccountAccessConsentsConsentIDBadRequest() *GetAccountAccessConsentsConsentIDBadRequest {
	return &GetAccountAccessConsentsConsentIDBadRequest{}
}

/*
GetAccountAccessConsentsConsentIDBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetAccountAccessConsentsConsentIDBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get account access consents consent Id bad request response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id bad request response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id bad request response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id bad request response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id bad request response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get account access consents consent Id bad request response
func (o *GetAccountAccessConsentsConsentIDBadRequest) Code() int {
	return 400
}

func (o *GetAccountAccessConsentsConsentIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetAccountAccessConsentsConsentIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetAccountAccessConsentsConsentIDBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetAccountAccessConsentsConsentIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDUnauthorized creates a GetAccountAccessConsentsConsentIDUnauthorized with default headers values
func NewGetAccountAccessConsentsConsentIDUnauthorized() *GetAccountAccessConsentsConsentIDUnauthorized {
	return &GetAccountAccessConsentsConsentIDUnauthorized{}
}

/*
GetAccountAccessConsentsConsentIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAccountAccessConsentsConsentIDUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get account access consents consent Id unauthorized response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id unauthorized response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id unauthorized response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id unauthorized response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id unauthorized response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get account access consents consent Id unauthorized response
func (o *GetAccountAccessConsentsConsentIDUnauthorized) Code() int {
	return 401
}

func (o *GetAccountAccessConsentsConsentIDUnauthorized) Error() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdUnauthorized", 401)
}

func (o *GetAccountAccessConsentsConsentIDUnauthorized) String() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdUnauthorized", 401)
}

func (o *GetAccountAccessConsentsConsentIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDForbidden creates a GetAccountAccessConsentsConsentIDForbidden with default headers values
func NewGetAccountAccessConsentsConsentIDForbidden() *GetAccountAccessConsentsConsentIDForbidden {
	return &GetAccountAccessConsentsConsentIDForbidden{}
}

/*
GetAccountAccessConsentsConsentIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetAccountAccessConsentsConsentIDForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get account access consents consent Id forbidden response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id forbidden response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id forbidden response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id forbidden response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id forbidden response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get account access consents consent Id forbidden response
func (o *GetAccountAccessConsentsConsentIDForbidden) Code() int {
	return 403
}

func (o *GetAccountAccessConsentsConsentIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetAccountAccessConsentsConsentIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetAccountAccessConsentsConsentIDForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetAccountAccessConsentsConsentIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDMethodNotAllowed creates a GetAccountAccessConsentsConsentIDMethodNotAllowed with default headers values
func NewGetAccountAccessConsentsConsentIDMethodNotAllowed() *GetAccountAccessConsentsConsentIDMethodNotAllowed {
	return &GetAccountAccessConsentsConsentIDMethodNotAllowed{}
}

/*
GetAccountAccessConsentsConsentIDMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type GetAccountAccessConsentsConsentIDMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get account access consents consent Id method not allowed response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id method not allowed response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id method not allowed response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id method not allowed response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id method not allowed response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get account access consents consent Id method not allowed response
func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) Code() int {
	return 405
}

func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetAccountAccessConsentsConsentIDMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDNotAcceptable creates a GetAccountAccessConsentsConsentIDNotAcceptable with default headers values
func NewGetAccountAccessConsentsConsentIDNotAcceptable() *GetAccountAccessConsentsConsentIDNotAcceptable {
	return &GetAccountAccessConsentsConsentIDNotAcceptable{}
}

/*
GetAccountAccessConsentsConsentIDNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type GetAccountAccessConsentsConsentIDNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get account access consents consent Id not acceptable response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id not acceptable response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id not acceptable response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id not acceptable response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id not acceptable response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get account access consents consent Id not acceptable response
func (o *GetAccountAccessConsentsConsentIDNotAcceptable) Code() int {
	return 406
}

func (o *GetAccountAccessConsentsConsentIDNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdNotAcceptable", 406)
}

func (o *GetAccountAccessConsentsConsentIDNotAcceptable) String() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdNotAcceptable", 406)
}

func (o *GetAccountAccessConsentsConsentIDNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetAccountAccessConsentsConsentIDTooManyRequests creates a GetAccountAccessConsentsConsentIDTooManyRequests with default headers values
func NewGetAccountAccessConsentsConsentIDTooManyRequests() *GetAccountAccessConsentsConsentIDTooManyRequests {
	return &GetAccountAccessConsentsConsentIDTooManyRequests{}
}

/*
GetAccountAccessConsentsConsentIDTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetAccountAccessConsentsConsentIDTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get account access consents consent Id too many requests response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id too many requests response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id too many requests response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get account access consents consent Id too many requests response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get account access consents consent Id too many requests response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get account access consents consent Id too many requests response
func (o *GetAccountAccessConsentsConsentIDTooManyRequests) Code() int {
	return 429
}

func (o *GetAccountAccessConsentsConsentIDTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdTooManyRequests", 429)
}

func (o *GetAccountAccessConsentsConsentIDTooManyRequests) String() string {
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdTooManyRequests", 429)
}

func (o *GetAccountAccessConsentsConsentIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetAccountAccessConsentsConsentIDInternalServerError creates a GetAccountAccessConsentsConsentIDInternalServerError with default headers values
func NewGetAccountAccessConsentsConsentIDInternalServerError() *GetAccountAccessConsentsConsentIDInternalServerError {
	return &GetAccountAccessConsentsConsentIDInternalServerError{}
}

/*
GetAccountAccessConsentsConsentIDInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetAccountAccessConsentsConsentIDInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get account access consents consent Id internal server error response has a 2xx status code
func (o *GetAccountAccessConsentsConsentIDInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get account access consents consent Id internal server error response has a 3xx status code
func (o *GetAccountAccessConsentsConsentIDInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get account access consents consent Id internal server error response has a 4xx status code
func (o *GetAccountAccessConsentsConsentIDInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get account access consents consent Id internal server error response has a 5xx status code
func (o *GetAccountAccessConsentsConsentIDInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get account access consents consent Id internal server error response a status code equal to that given
func (o *GetAccountAccessConsentsConsentIDInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get account access consents consent Id internal server error response
func (o *GetAccountAccessConsentsConsentIDInternalServerError) Code() int {
	return 500
}

func (o *GetAccountAccessConsentsConsentIDInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetAccountAccessConsentsConsentIDInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /account-access-consents/{ConsentId}][%d] getAccountAccessConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetAccountAccessConsentsConsentIDInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetAccountAccessConsentsConsentIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	o.Payload = new(models.OBErrorResponse1)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
