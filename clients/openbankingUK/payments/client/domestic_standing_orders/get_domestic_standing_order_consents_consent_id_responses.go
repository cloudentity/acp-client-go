// Code generated by go-swagger; DO NOT EDIT.

package domestic_standing_orders

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

// GetDomesticStandingOrderConsentsConsentIDReader is a Reader for the GetDomesticStandingOrderConsentsConsentID structure.
type GetDomesticStandingOrderConsentsConsentIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDomesticStandingOrderConsentsConsentIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDomesticStandingOrderConsentsConsentIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetDomesticStandingOrderConsentsConsentIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetDomesticStandingOrderConsentsConsentIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDomesticStandingOrderConsentsConsentIDForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetDomesticStandingOrderConsentsConsentIDNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 405:
		result := NewGetDomesticStandingOrderConsentsConsentIDMethodNotAllowed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 406:
		result := NewGetDomesticStandingOrderConsentsConsentIDNotAcceptable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDomesticStandingOrderConsentsConsentIDTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetDomesticStandingOrderConsentsConsentIDInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /domestic-standing-order-consents/{ConsentId}] GetDomesticStandingOrderConsentsConsentId", response, response.Code())
	}
}

// NewGetDomesticStandingOrderConsentsConsentIDOK creates a GetDomesticStandingOrderConsentsConsentIDOK with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDOK() *GetDomesticStandingOrderConsentsConsentIDOK {
	return &GetDomesticStandingOrderConsentsConsentIDOK{}
}

/*
GetDomesticStandingOrderConsentsConsentIDOK describes a response with status code 200, with default header values.

Domestic Standing Order Consents Read
*/
type GetDomesticStandingOrderConsentsConsentIDOK struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBWriteDomesticStandingOrderConsentResponse6
}

// IsSuccess returns true when this get domestic standing order consents consent Id o k response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get domestic standing order consents consent Id o k response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id o k response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic standing order consents consent Id o k response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id o k response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get domestic standing order consents consent Id o k response
func (o *GetDomesticStandingOrderConsentsConsentIDOK) Code() int {
	return 200
}

func (o *GetDomesticStandingOrderConsentsConsentIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdOK %s", 200, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdOK %s", 200, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDOK) GetPayload() *models.OBWriteDomesticStandingOrderConsentResponse6 {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentsConsentIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.OBWriteDomesticStandingOrderConsentResponse6)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticStandingOrderConsentsConsentIDBadRequest creates a GetDomesticStandingOrderConsentsConsentIDBadRequest with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDBadRequest() *GetDomesticStandingOrderConsentsConsentIDBadRequest {
	return &GetDomesticStandingOrderConsentsConsentIDBadRequest{}
}

/*
GetDomesticStandingOrderConsentsConsentIDBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type GetDomesticStandingOrderConsentsConsentIDBadRequest struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get domestic standing order consents consent Id bad request response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id bad request response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id bad request response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id bad request response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id bad request response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get domestic standing order consents consent Id bad request response
func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) Code() int {
	return 400
}

func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdBadRequest %s", 400, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentsConsentIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDomesticStandingOrderConsentsConsentIDUnauthorized creates a GetDomesticStandingOrderConsentsConsentIDUnauthorized with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDUnauthorized() *GetDomesticStandingOrderConsentsConsentIDUnauthorized {
	return &GetDomesticStandingOrderConsentsConsentIDUnauthorized{}
}

/*
GetDomesticStandingOrderConsentsConsentIDUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetDomesticStandingOrderConsentsConsentIDUnauthorized struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get domestic standing order consents consent Id unauthorized response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id unauthorized response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id unauthorized response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id unauthorized response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id unauthorized response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get domestic standing order consents consent Id unauthorized response
func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) Code() int {
	return 401
}

func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) Error() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdUnauthorized", 401)
}

func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) String() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdUnauthorized", 401)
}

func (o *GetDomesticStandingOrderConsentsConsentIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetDomesticStandingOrderConsentsConsentIDForbidden creates a GetDomesticStandingOrderConsentsConsentIDForbidden with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDForbidden() *GetDomesticStandingOrderConsentsConsentIDForbidden {
	return &GetDomesticStandingOrderConsentsConsentIDForbidden{}
}

/*
GetDomesticStandingOrderConsentsConsentIDForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetDomesticStandingOrderConsentsConsentIDForbidden struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get domestic standing order consents consent Id forbidden response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id forbidden response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id forbidden response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id forbidden response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id forbidden response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get domestic standing order consents consent Id forbidden response
func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) Code() int {
	return 403
}

func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdForbidden %s", 403, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentsConsentIDForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDomesticStandingOrderConsentsConsentIDNotFound creates a GetDomesticStandingOrderConsentsConsentIDNotFound with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDNotFound() *GetDomesticStandingOrderConsentsConsentIDNotFound {
	return &GetDomesticStandingOrderConsentsConsentIDNotFound{}
}

/*
GetDomesticStandingOrderConsentsConsentIDNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetDomesticStandingOrderConsentsConsentIDNotFound struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get domestic standing order consents consent Id not found response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id not found response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id not found response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id not found response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id not found response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get domestic standing order consents consent Id not found response
func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) Code() int {
	return 404
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) Error() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdNotFound", 404)
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) String() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdNotFound", 404)
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetDomesticStandingOrderConsentsConsentIDMethodNotAllowed creates a GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDMethodNotAllowed() *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed {
	return &GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed{}
}

/*
GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed describes a response with status code 405, with default header values.

Method Not Allowed
*/
type GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get domestic standing order consents consent Id method not allowed response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id method not allowed response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id method not allowed response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id method not allowed response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id method not allowed response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) IsCode(code int) bool {
	return code == 405
}

// Code gets the status code for the get domestic standing order consents consent Id method not allowed response
func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) Code() int {
	return 405
}

func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) Error() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) String() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdMethodNotAllowed", 405)
}

func (o *GetDomesticStandingOrderConsentsConsentIDMethodNotAllowed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetDomesticStandingOrderConsentsConsentIDNotAcceptable creates a GetDomesticStandingOrderConsentsConsentIDNotAcceptable with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDNotAcceptable() *GetDomesticStandingOrderConsentsConsentIDNotAcceptable {
	return &GetDomesticStandingOrderConsentsConsentIDNotAcceptable{}
}

/*
GetDomesticStandingOrderConsentsConsentIDNotAcceptable describes a response with status code 406, with default header values.

Not Acceptable
*/
type GetDomesticStandingOrderConsentsConsentIDNotAcceptable struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get domestic standing order consents consent Id not acceptable response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id not acceptable response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id not acceptable response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id not acceptable response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id not acceptable response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) IsCode(code int) bool {
	return code == 406
}

// Code gets the status code for the get domestic standing order consents consent Id not acceptable response
func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) Code() int {
	return 406
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) Error() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdNotAcceptable", 406)
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) String() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdNotAcceptable", 406)
}

func (o *GetDomesticStandingOrderConsentsConsentIDNotAcceptable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header x-fapi-interaction-id
	hdrXFapiInteractionID := response.GetHeader("x-fapi-interaction-id")

	if hdrXFapiInteractionID != "" {
		o.XFapiInteractionID = hdrXFapiInteractionID
	}

	return nil
}

// NewGetDomesticStandingOrderConsentsConsentIDTooManyRequests creates a GetDomesticStandingOrderConsentsConsentIDTooManyRequests with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDTooManyRequests() *GetDomesticStandingOrderConsentsConsentIDTooManyRequests {
	return &GetDomesticStandingOrderConsentsConsentIDTooManyRequests{}
}

/*
GetDomesticStandingOrderConsentsConsentIDTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type GetDomesticStandingOrderConsentsConsentIDTooManyRequests struct {

	/* Number in seconds to wait
	 */
	RetryAfter int64

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string
}

// IsSuccess returns true when this get domestic standing order consents consent Id too many requests response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id too many requests response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id too many requests response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic standing order consents consent Id too many requests response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic standing order consents consent Id too many requests response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get domestic standing order consents consent Id too many requests response
func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) Code() int {
	return 429
}

func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdTooManyRequests", 429)
}

func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) String() string {
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdTooManyRequests", 429)
}

func (o *GetDomesticStandingOrderConsentsConsentIDTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewGetDomesticStandingOrderConsentsConsentIDInternalServerError creates a GetDomesticStandingOrderConsentsConsentIDInternalServerError with default headers values
func NewGetDomesticStandingOrderConsentsConsentIDInternalServerError() *GetDomesticStandingOrderConsentsConsentIDInternalServerError {
	return &GetDomesticStandingOrderConsentsConsentIDInternalServerError{}
}

/*
GetDomesticStandingOrderConsentsConsentIDInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetDomesticStandingOrderConsentsConsentIDInternalServerError struct {

	/* An RFC4122 UID used as a correlation id.
	 */
	XFapiInteractionID string

	/* Header containing a detached JWS signature of the body of the payload.

	 */
	XJwsSignature string

	Payload *models.OBErrorResponse1
}

// IsSuccess returns true when this get domestic standing order consents consent Id internal server error response has a 2xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic standing order consents consent Id internal server error response has a 3xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic standing order consents consent Id internal server error response has a 4xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic standing order consents consent Id internal server error response has a 5xx status code
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get domestic standing order consents consent Id internal server error response a status code equal to that given
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get domestic standing order consents consent Id internal server error response
func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) Code() int {
	return 500
}

func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /domestic-standing-order-consents/{ConsentId}][%d] getDomesticStandingOrderConsentsConsentIdInternalServerError %s", 500, payload)
}

func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) GetPayload() *models.OBErrorResponse1 {
	return o.Payload
}

func (o *GetDomesticStandingOrderConsentsConsentIDInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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
