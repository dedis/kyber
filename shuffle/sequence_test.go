package shuffle

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
)

func TestAssertXY(t *testing.T) {
	type tdata struct {
		x      [][]kyber.Point
		y      [][]kyber.Point
		errStr string
	}

	// express possible wrong cases and the expected errors

	table := []tdata{
		{
			x:      nil,
			y:      nil,
			errStr: "array X is empty",
		},
		{
			x:      [][]kyber.Point{{}},
			y:      [][]kyber.Point{{}},
			errStr: "array X is empty",
		},
		{
			x:      [][]kyber.Point{make([]kyber.Point, 1)},
			y:      [][]kyber.Point{{}},
			errStr: "array Y is empty",
		},
		{
			x:      [][]kyber.Point{make([]kyber.Point, 1)},
			y:      nil,
			errStr: "array Y is empty",
		},
		{
			x:      [][]kyber.Point{make([]kyber.Point, 1), make([]kyber.Point, 2)},
			y:      [][]kyber.Point{make([]kyber.Point, 1)},
			errStr: "arrays X and Y have a different size: 2 != 1",
		},
		{
			x:      [][]kyber.Point{make([]kyber.Point, 1)},
			y:      [][]kyber.Point{make([]kyber.Point, 2)},
			errStr: "array Y[0] has unexpected size: 1 != 2",
		},
		{
			x:      [][]kyber.Point{make([]kyber.Point, 1), make([]kyber.Point, 2)},
			y:      [][]kyber.Point{make([]kyber.Point, 1), make([]kyber.Point, 1)},
			errStr: "array X[1] has unexpected size: 1 != 2",
		},
	}

	for _, entry := range table {
		err := assertXY(entry.x, entry.y)
		require.EqualError(t, err, entry.errStr)
	}

	// check valid data

	x := [][]kyber.Point{make([]kyber.Point, 2), make([]kyber.Point, 2)}
	y := [][]kyber.Point{make([]kyber.Point, 2), make([]kyber.Point, 2)}

	err := assertXY(x, y)
	require.NoError(t, err)
}
