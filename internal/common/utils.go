package common

import (
	"crypto/subtle"
	"fmt"

	"github.com/google/uuid"
)

func MatchPath() {

}

// Find returns the index where it found the target in the array.
// Returns -1 if it isn't found.
func Find[T comparable](xs []T, target T) int {
	for i, x := range xs {
		if x == target {
			return i
		}
	}
	return -1
}

// FindFunc returns the index where the predicate matched in the array.
// Returns -1 if it isn't found.
func FindFunc[T interface{}](f func(T) bool, xs []T) int {
	for i, x := range xs {
		if f(x) {
			return i
		}
	}
	return -1
}

// GetRandomString returns a random fixed length string
func GetRandomString() string {
	return uuid.New().String()
}

// ContantTimeEqual returns true if 2 strings are equal in constant time
func ContantTimeEqual(x, y string) bool {
	return subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1
}

// InterfaceSlicetoTSlice converts a slice of interfaces to a slice of a specific type.
func InterfaceSlicetoTSlice[T interface{}](xIs []interface{}) ([]T, error) {
	xs := []T{}
	for _, xI := range xIs {
		x, ok := xI.(T)
		if !ok {
			return xs, fmt.Errorf("expected a string. actual: %T %+v", xI, xI)
		}
		xs = append(xs, x)
	}
	return xs, nil
}

// Apply applies a function to every element in the slice.
func Apply[T1 interface{}, T2 interface{}](f func(T1) T2, xs []T1) []T2 {
	ys := []T2{}
	for _, x := range xs {
		ys = append(ys, f(x))
	}
	return ys
}

// Filter creates a new slice containing all the elements
// from the original slice that satisfy a predicate.
func Filter[T interface{}](f func(T) bool, xs []T) []T {
	ys := []T{}
	for _, x := range xs {
		if f(x) {
			ys = append(ys, x)
		}
	}
	return ys
}

func AppendIfNotPresent[T comparable](xs []T, ys ...T) []T {
	for _, y := range ys {
		if Find(xs, y) == -1 {
			xs = append(xs, y)
		}
	}
	return xs
}
