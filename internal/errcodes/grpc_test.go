// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package errcodes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

func TestKindOfGRPC(t *testing.T) {
	for _, c := range []codes.Code{codes.AlreadyExists, codes.FailedPrecondition, codes.InvalidArgument, codes.NotFound,
		codes.OutOfRange, codes.PermissionDenied, codes.ResourceExhausted, codes.Unauthenticated} {
		assert.Equal(t, KindBusiness, KindOfGRPC(c), c.String())
	}
	for _, c := range []codes.Code{codes.OK, codes.Aborted, codes.Canceled, codes.DataLoss, codes.DeadlineExceeded,
		codes.Internal, codes.Unavailable, codes.Unimplemented, codes.Unknown} {
		assert.Equal(t, KindReach, KindOfGRPC(c), c.String())
	}
}
