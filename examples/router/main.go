// Constructs a native route and exits without a server or API request.
package main

import (
	"context"
	"fmt"
	sdk "github.com/fxmacrodata/fxmacrodata-go"
	fxmdhttprouter "github.com/fxmacrodata/httprouter-fxmacrodata"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func main() {
	client, err := fxmdhttprouter.NewClient("", fxmdhttprouter.Options{})
	if err != nil {
		panic(err)
	}
	router := httprouter.New()
	authorize := func(*http.Request) bool { return false }
	err = client.MountSDK(router, "GET", "/macro/calendar/:currency", authorize, func(ctx context.Context, api *sdk.APIClient, in *http.Request) error {
		_, _, err := api.FXMacroDataAPI.GetCalendar(ctx, httprouter.ParamsFromContext(in.Context()).ByName("currency")).Execute()
		return err
	})
	if err != nil {
		panic(err)
	}
	handle, params, redirect := router.Lookup("GET", "/macro/calendar/USD")
	if handle == nil || redirect {
		panic("route lookup failed")
	}
	fmt.Println("Constructed policy-protected HTTPRouter route; parameter:", params.ByName("currency"), "; no server started or API called.")
}
