package forwardproxy

import (
	"crypto/tls"
	"fmt"
	"github.com/megaease/easegress/pkg/context"
	"github.com/megaease/easegress/pkg/filter/proxy"
	"github.com/megaease/easegress/pkg/logger"
	"github.com/megaease/easegress/pkg/object/httppipeline"
	"github.com/megaease/easegress/pkg/util/callbackreader"
	"github.com/megaease/easegress/pkg/util/httpstat"
	"github.com/megaease/easegress/pkg/util/stringtool"
	gohttpstat "github.com/tcnksm/go-httpstat"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	resultInternalError = "internalError"
	resultRequestError = "requestError"
	resultClientError   = "clientError"
	resultServerError   = "serverError"

	// Kind is the kind of AutoCertManager.
	Kind = "ForwardProxy"

	MasaForwardIP   = "x-masa-forward-ip"
	MasaForwardPort = "x-masa-forward-port"

	supportProtocol = "http"
)

var results = []string{
	resultInternalError,
	resultRequestError,
	resultClientError,
	resultServerError,
}



type (
	ForwardProxy struct {
		filterSpec *httppipeline.FilterSpec
		spec       *Spec
		client     *http.Client
		httpStat   *httpstat.HTTPStat
	}

	Spec struct {
		MaxIdleConns        int              `yaml:"maxIdleConns" jsonschema:"omitempty"`
		MaxIdleConnsPerHost int              `yaml:"maxIdleConnsPerHost" jsonschema:"omitempty"`
		IdleConnTimeout     int              `yaml:"idleConnTimeout" jsonschema:"omitempty"`
	}
)

func (s Spec) Validate() error {
	if s.IdleConnTimeout <= 0 {
		return fmt.Errorf("IdleConnTimeout should be positive num")
	}

	if s.MaxIdleConns <= 0 {
		return fmt.Errorf("MaxIdleConns should be positive num")
	}

	if s.IdleConnTimeout <= 0 {
		return fmt.Errorf("IdleConnTimeout should be positive num")
	}

	return nil
}

func init() {
	httppipeline.Register(&ForwardProxy{})
}

func (f *ForwardProxy) Kind() string {
	return Kind
}

func (f *ForwardProxy) DefaultSpec() interface{} {
	return &Spec{
		MaxIdleConns: 200,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 120,
	}
}

func (f *ForwardProxy) Description() string {
	return "ForwardProxy proxy for client"
}

func (f *ForwardProxy) Results() []string {
	return results
}

func (f *ForwardProxy) Init(filterSpec *httppipeline.FilterSpec) {
	f.filterSpec, f.spec = filterSpec, filterSpec.FilterSpec().(*Spec)
	f.reload()
}

func (f *ForwardProxy) reload() {
	f.httpStat = httpstat.New()
	f.client = &http.Client{
		// NOTE: Timeout could be no limit, real client or server could cancel it.
		Timeout: 0,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 60 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig:    &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
			DisableCompression: false,
			// NOTE: The large number of Idle Connections can
			// reduce overhead of building connections.
			MaxIdleConns:          f.spec.MaxIdleConns,
			MaxIdleConnsPerHost:   f.spec.MaxIdleConnsPerHost,
			IdleConnTimeout:       time.Duration(f.spec.IdleConnTimeout) * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (f *ForwardProxy) Inherit(filterSpec *httppipeline.FilterSpec, previousGeneration httppipeline.Filter) {
	previousGeneration.Close()
	f.Init(filterSpec)
}

var httpStatMetricPool = &sync.Pool{
	New: func() interface{} {
		return &httpstat.Metric{}
	},
}

var requestPool = &sync.Pool{
	New: func() interface{} {
		return &request{}
	},
}

var httpStatResultPool = &sync.Pool{
	New: func() interface{} {
		return &gohttpstat.Result{}
	},
}

func (f *ForwardProxy) Handle(context context.HTTPContext) (result string) {
	result = f.handle(context)
	return context.CallNextHandler(result)
}

func (f ForwardProxy) handle(ctx context.HTTPContext) string {
	setStatusCode := func(code int) {
		ctx.Lock()
		ctx.Response().SetStatusCode(code)
		ctx.Unlock()
	}
	headers := ctx.Request().Header()
	targetIP := headers.Get(MasaForwardIP)
	targetPort := headers.Get(MasaForwardPort)
	if targetIP == "" || targetPort == "" {
		logger.Errorf("request header is invalid: ip %s, port", targetIP, targetPort)
		setStatusCode(http.StatusBadRequest)
		return resultRequestError
	}

	schema := ctx.Request().Scheme()
	if schema == "" {
		schema = supportProtocol
	}
	if schema != supportProtocol {
		logger.Errorf("request schema is invalid, only support http, now schema is %s", schema)
		setStatusCode(http.StatusBadRequest)
		return resultRequestError
	}

	targetAddress := schema + "://" + targetIP+":" + targetPort
	logger.LazyDebug(func() string {
		return "forward proxy target address is " + targetAddress
	})

	req, err := f.prepareRequest(ctx, targetAddress, ctx.Request().Body(), requestPool, httpStatResultPool)
	if err != nil {
		msg := stringtool.Cat("prepare request failed: ", err.Error())
		logger.Errorf("BUG: %s", msg)
		setStatusCode(http.StatusInternalServerError)
		return resultInternalError
	}

	resp, err := f.doRequest(req)
	if err != nil {
		// NOTE: May add option to cancel the tracing if failed here.
		// ctx.Span().Cancel()
		if ctx.ClientDisconnected() {
			// NOTE: The HTTPContext will set 499 by itself if client is Disconnected.
			// w.SetStatusCode((499)
			return resultClientError
		}

		setStatusCode(http.StatusServiceUnavailable)
		return resultServerError
	}

	ctx.Lock()
	defer ctx.Unlock()
	// NOTE: The code below can't use addTag and setStatusCode in case of deadlock.

	respBody := f.statRequestResponse(ctx, req, resp)

	ctx.Response().SetStatusCode(resp.StatusCode)
	ctx.Response().Header().AddFromStd(resp.Header)
	ctx.Response().SetBody(respBody)

	return ""
}

func (f *ForwardProxy) statRequestResponse(ctx context.HTTPContext,
	req *request, resp *http.Response) io.Reader {

	var count int

	callbackBody := callbackreader.New(resp.Body)
	callbackBody.OnAfter(func(num int, p []byte, n int, err error) ([]byte, int, error) {
		count += n
		if err == io.EOF {
			req.finish()
		}

		return p, n, err
	})

	ctx.OnFinish(func() {
		duration := req.total()
		metric := httpStatMetricPool.Get().(*httpstat.Metric)
		metric.StatusCode = resp.StatusCode
		metric.Duration = duration
		metric.ReqSize = ctx.Request().Size()
		metric.RespSize = uint64(proxy.ResponseMetaSize(resp) + count)

		f.httpStat.Stat(metric)
		// recycle struct instances
		httpStatMetricPool.Put(metric)
		httpStatResultPool.Put(req.statResult)
		requestPool.Put(req)
	})

	return callbackBody
}

func (f *ForwardProxy) doRequest(req *request) (*http.Response, error) {
	req.start()
	resp, err := f.client.Do(req.std)
	if err != nil {
		return nil, err
	}
	return resp, nil
}



func (f *ForwardProxy) Status() interface{} {
	return "UP"
}

func (f *ForwardProxy) Close() {

}
