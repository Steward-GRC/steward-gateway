// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package errcodes

import "google.golang.org/grpc/codes"

// grpcKinds classifies a relayed status, where only the gRPC code (not the
// other service's registry) is on the wire.
var grpcKinds = map[codes.Code]Kind{
	codes.AlreadyExists:      KindBusiness,
	codes.FailedPrecondition: KindBusiness,
	codes.InvalidArgument:    KindBusiness,
	codes.NotFound:           KindBusiness,
	codes.OutOfRange:         KindBusiness,
	codes.PermissionDenied:   KindBusiness,
	codes.ResourceExhausted:  KindBusiness,
	codes.Unauthenticated:    KindBusiness,
}

// KindOfGRPC classifies a backend's status code: the client-facing outcomes
// and a spent quota are business, every fault and transport failure is reach.
func KindOfGRPC(c codes.Code) Kind {
	if k, ok := grpcKinds[c]; ok {
		return k
	}
	return KindReach
}
