package types

// PermTicket contains the ticket used in the UMA grant flow
type PermTicket struct {
	Ticket string `json:"ticket"`
}

const (
	// UMA_GRANT_TYPE is the grant type for the UMA grant flow to get the RPT
	// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#uma-grant-type
	UMA_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket"
)
