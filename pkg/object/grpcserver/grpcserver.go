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

package grpcserver

import (
	"github.com/megaease/easegress/pkg/context"
	"github.com/megaease/easegress/pkg/supervisor"
)

const (
	// Category is the category of GRPCServer.
	Category = supervisor.CategoryTrafficGate

	// Kind is the kind of HTTPServer.
	Kind = "GRPCServer"
)

func init() {
	supervisor.Register(&GrpcServer{})
}

type (
	// GrpcServer is TrafficGate Object GrpcServer
	GrpcServer struct {
		runtime *runtime
	}
)

// Category returns the category of GrpcServer.
func (g *GrpcServer) Category() supervisor.ObjectCategory {
	return Category
}

// Kind returns the kind of GrpcServer.
func (g *GrpcServer) Kind() string {
	return Kind
}

// DefaultSpec returns the default Spec of GrpcServer.
func (g *GrpcServer) DefaultSpec() interface{} {
	return &Spec{
		MaxConnectionIdle: "60s",
		MaxConnections:    10240,
	}
}

// Status returns the status of GrpcServer.
func (g *GrpcServer) Status() *supervisor.Status {
	return &supervisor.Status{
		ObjectStatus: g.runtime.Status(),
	}
}

// Close close GrpcServer
func (g *GrpcServer) Close() {
	g.runtime.Close()
}

// Init first create GrpcServer by Spec.name
func (g *GrpcServer) Init(superSpec *supervisor.Spec, muxMapper context.MuxMapper) {
	g.runtime = newRuntime(superSpec, muxMapper)
	g.runtime.eventChan <- &eventReload{
		nextSuperSpec: superSpec,
		muxMapper:     muxMapper,
	}
}

// Inherit inherits previous generation of GrpcServer.
func (g *GrpcServer) Inherit(superSpec *supervisor.Spec, previousGeneration supervisor.Object, muxMapper context.MuxMapper) {
	g.runtime = previousGeneration.(*GrpcServer).runtime
	g.runtime.eventChan <- &eventReload{
		nextSuperSpec: superSpec,
		muxMapper:     muxMapper,
	}
}
