package httpclient

import "context"

type requestBudgetKey struct{}

// WithRequestBudget attaches a scan allocation to every physical request,
// including redirects, retries and externally reserved protocol requests.
func WithRequestBudget(ctx context.Context, reserve func() error) context.Context {
	return context.WithValue(ctx, requestBudgetKey{}, reserve)
}

func ReserveRequestBudget(ctx context.Context) error {
	if reserve, ok := ctx.Value(requestBudgetKey{}).(func() error); ok && reserve != nil {
		return reserve()
	}
	return nil
}

// RequestBudgetAtTransport lets instrumentation avoid charging a logical HTTP
// call twice. Test and alternative clients are charged at their Do boundary.
func (c *Client) RequestBudgetAtTransport() bool { return true }
