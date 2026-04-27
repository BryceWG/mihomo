package route

import (
	"context"
	"math"

	"github.com/metacubex/mihomo/component/resolver"
	coreDNS "github.com/metacubex/mihomo/dns"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

func dnsRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/query", queryDNS)
	r.Get("/stats", dnsStats)
	r.Post("/stats/reset", resetDNSStats)
	return r
}

func queryDNS(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}

	name := r.URL.Query().Get("name")
	qTypeStr, _ := lo.Coalesce(r.URL.Query().Get("type"), "A")

	qType, exist := D.StringToType[qTypeStr]
	if !exist {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid query type"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	msg := D.Msg{}
	msg.SetQuestion(D.Fqdn(name), qType)
	resp, err := resolver.DefaultResolver.ExchangeContext(ctx, &msg)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	responseData := render.M{
		"Status":   resp.Rcode,
		"Question": resp.Question,
		"TC":       resp.Truncated,
		"RD":       resp.RecursionDesired,
		"RA":       resp.RecursionAvailable,
		"AD":       resp.AuthenticatedData,
		"CD":       resp.CheckingDisabled,
	}

	rr2Json := func(rr D.RR, _ int) render.M {
		header := rr.Header()
		return render.M{
			"name": header.Name,
			"type": header.Rrtype,
			"TTL":  header.Ttl,
			"data": lo.Substring(rr.String(), len(header.String()), math.MaxUint),
		}
	}

	if len(resp.Answer) > 0 {
		responseData["Answer"] = lo.Map(resp.Answer, rr2Json)
	}
	if len(resp.Ns) > 0 {
		responseData["Authority"] = lo.Map(resp.Ns, rr2Json)
	}
	if len(resp.Extra) > 0 {
		responseData["Additional"] = lo.Map(resp.Extra, rr2Json)
	}

	render.JSON(w, r, responseData)
}

func dnsStats(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}
	statsReader, ok := resolver.DefaultResolver.(interface {
		DNSStats() coreDNS.DNSStatsSnapshot
	})
	if !ok {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS stats is unavailable"))
		return
	}

	render.JSON(w, r, statsReader.DNSStats())
}

func resetDNSStats(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}
	statsResetter, ok := resolver.DefaultResolver.(interface {
		ResetDNSStats()
	})
	if !ok {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS stats is unavailable"))
		return
	}

	statsResetter.ResetDNSStats()
	render.NoContent(w, r)
}
