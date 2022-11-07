package types

import "fmt"

var (
	// ErrAlreadyExist is the error returned when the given id is already present in the bucket in the database.
	ErrAlreadyExist = fmt.Errorf("id already exists")
	// ErrNotFound is the error returned when the given id is not present in the bucket in the database.
	ErrNotFound = fmt.Errorf("id was not found")
)
