/*
 * Copyright (c) 2017, MegaEase
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fallback

import (
	"io"
	"testing"

	"github.com/megaease/easegress/pkg/context"
	"github.com/megaease/easegress/pkg/filters"
	"github.com/megaease/easegress/pkg/protocols/httpprot"
	"github.com/megaease/easegress/pkg/util/yamltool"
	"github.com/stretchr/testify/assert"
)

func TestFallback(t *testing.T) {
	assert := assert.New(t)
	const yamlSpec = `
kind: Fallback
name: fallback
mockCode: 203
mockHeaders:
  X-Mocked: true
mockBody: "mocked body"
`
	rawSpec := make(map[string]interface{})
	yamltool.Unmarshal([]byte(yamlSpec), &rawSpec)

	spec, e := filters.NewSpec(nil, "", rawSpec)
	if e != nil {
		t.Errorf("unexpected error: %v", e)
	}

	fb := kind.CreateInstance(spec)
	fb.Init()

	ctx := context.New(nil)
	httpresp, err := httpprot.NewResponse(nil)
	assert.Nil(err)
	ctx.SetResponse("resp1", httpresp)
	ctx.UseResponse("resp1")

	fb.Handle(ctx)
	if httpresp.StatusCode() != 203 {
		t.Error("status code is not correct")
	}
	payload, err := io.ReadAll(httpresp.GetPayload())
	assert.Nil(err)
	if string(payload) != "mocked body" {
		t.Error("body is not correct")
	}
	if httpresp.Header().Get("X-Mocked") != "true" {
		t.Error("header is not correct")
	}

	if fb.Status() != nil {
		t.Error("behavior changed, please update this case")
	}

	spec, _ = filters.NewSpec(nil, "", rawSpec)
	newFb := kind.CreateInstance(spec)
	newFb.Inherit(fb)
	fb.Close()

	httpresp, err = httpprot.NewResponse(nil)
	assert.Nil(err)
	ctx.SetResponse("resp2", httpresp)
	ctx.UseResponse("resp2")

	newFb.Handle(ctx)
	if httpresp.StatusCode() != 203 {
		t.Error("status code is not correct")
	}

	payload, err = io.ReadAll(httpresp.GetPayload())
	assert.Nil(err)
	if string(payload) != "mocked body" {
		t.Error("body is not correct")
	}
	if httpresp.Header().Get("X-Mocked") != "true" {
		t.Error("header is not correct")
	}
}