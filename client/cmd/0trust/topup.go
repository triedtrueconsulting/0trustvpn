package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0trust/cli/internal/api"
	"github.com/0trust/cli/internal/config"
)

// pollFor is how long `topup --wait` watches an invoice before giving up and
// telling the customer to come back. Crypto confirmation takes as long as it
// takes; the point of the cap is that the command ends rather than appearing
// to hang, and it says how to check again.
const pollFor = 30 * time.Minute

// cmdTopup extends the subscription this device is logged in to.
//
// It exists because the service already told every customer to run it. The
// renewal warning in api/sweep.py, the expiry notice, and web/trial.html all
// say `0trust topup` — and the command did not exist, so the one instruction
// the service gives a paying customer at the moment they are trying to give
// it money was wrong. The API endpoint was there the whole time; only the
// client half was missing.
func cmdTopup(args []string) error {
	months := 0
	currency := ""
	wait := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--months":
			if i+1 < len(args) {
				n, err := strconv.Atoi(args[i+1])
				if err != nil {
					return fmt.Errorf("--months takes a number")
				}
				months, i = n, i+1
			}
		case "--currency", "--coin":
			if i+1 < len(args) {
				currency, i = strings.ToUpper(args[i+1]), i+1
			}
		case "--wait":
			wait = true
		default:
			// A bare number is the obvious thing to type.
			if n, err := strconv.Atoi(args[i]); err == nil {
				months = n
			}
		}
	}

	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		return fmt.Errorf("not logged in — run: 0trust login")
	}
	c := api.New(st.APIBase, st.Token)

	// Show what the account has now, so a customer topping up early can see
	// they are stacking onto it rather than replacing it.
	if s, err := c.Status(); err == nil && s.ExpiresAt > 0 {
		fmt.Printf("  current plan expires %s (%s)\n",
			time.Unix(s.ExpiresAt, 0).Format("2006-01-02"),
			plural(s.DaysRemaining, "day"))
		fmt.Println("  months you add stack on top of that — nothing is lost")
		fmt.Println()
	}

	if months == 0 {
		return fmt.Errorf("how many months? try: 0trust topup 1   (or 3, or 12)")
	}

	resp, err := c.Topup(api.TopupReq{Months: months, Currency: currency})
	if err != nil {
		return err
	}
	fmt.Printf("→ invoice %s — $%.2f for %s\n",
		resp.InvoiceID, resp.AmountUSD, plural(months, "month"))

	methods, err := c.PaymentMethods(resp.InvoiceID)
	if err != nil {
		// The invoice is real and payable on the web even if this call
		// failed, so say so rather than implying nothing happened.
		fmt.Printf("⚠ could not fetch payment details (%v)\n", err)
		if resp.CheckoutURL != "" {
			fmt.Printf("  pay at: %s\n", resp.CheckoutURL)
		}
		return nil
	}

	switch {
	case len(methods.Methods) > 0:
		fmt.Println()
		for _, m := range methods.Methods {
			fmt.Printf("  %s\n", m.Currency)
			fmt.Printf("    address  %s\n", m.Address)
			if m.Amount != "" {
				fmt.Printf("    amount   %s %s\n", m.Amount, m.Currency)
			}
			if m.URI != "" {
				fmt.Printf("    uri      %s\n", m.URI)
			}
		}
		fmt.Println()
		fmt.Println("  Send the exact amount. The account extends on confirmation —")
		fmt.Println("  you do not need to tell us, and there is nothing to click.")
	case methods.CheckoutURL != "":
		fmt.Printf("\n  pay at: %s\n", methods.CheckoutURL)
	default:
		fmt.Println("\n⚠ this deployment returned no way to pay this invoice")
		return fmt.Errorf("no payment method available")
	}

	fmt.Printf("\n  check later with:  0trust topup --status %s\n", resp.InvoiceID)
	if !wait {
		return nil
	}
	return watchInvoice(c, resp.InvoiceID)
}

// watchInvoice polls until the invoice settles or the cap runs out.
func watchInvoice(c *api.Client, id string) error {
	fmt.Printf("\n  waiting for confirmation (Ctrl-C is safe — payment still counts)\n")
	deadline := time.Now().Add(pollFor)
	last := ""
	for time.Now().Before(deadline) {
		s, err := c.PaymentStatus(id)
		if err == nil {
			state := s.Status
			if s.Required > 0 {
				state = fmt.Sprintf("%s (%d/%d confirmations)",
					s.Status, s.Confirmations, s.Required)
			}
			if state != last {
				fmt.Printf("    %s\n", state)
				last = state
			}
			if strings.EqualFold(s.Status, "settled") ||
				strings.EqualFold(s.Status, "paid") ||
				strings.EqualFold(s.Status, "complete") {
				fmt.Println("\n✓ paid — the account has been extended")
				if st, err := c.Status(); err == nil && st.ExpiresAt > 0 {
					fmt.Printf("  now expires %s\n",
						time.Unix(st.ExpiresAt, 0).Format("2006-01-02"))
				}
				return nil
			}
		}
		time.Sleep(20 * time.Second)
	}
	fmt.Fprintf(os.Stderr,
		"\n  still unconfirmed after %s. That is not a failure — crypto takes\n"+
			"  as long as it takes. Check with: 0trust topup --status %s\n",
		pollFor, id)
	return nil
}

// cmdTopupStatus reports one invoice without opening another. Separated so a
// customer checking on a payment cannot accidentally create a second one.
func cmdTopupStatus(id string) error {
	st, err := config.Load()
	if err != nil {
		return err
	}
	c := api.New(st.APIBase, st.Token)
	s, err := c.PaymentStatus(id)
	if err != nil {
		return err
	}
	fmt.Printf("  invoice %s: %s", id, s.Status)
	if s.Required > 0 {
		fmt.Printf(" (%d/%d confirmations)", s.Confirmations, s.Required)
	}
	fmt.Println()
	return nil
}
