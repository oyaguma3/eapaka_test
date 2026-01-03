package eap

// MethodMismatchPolicy defines how to handle method mismatches.
type MethodMismatchPolicy string

const (
	MethodMismatchStrict MethodMismatchPolicy = "strict"
	MethodMismatchWarn   MethodMismatchPolicy = "warn"
	MethodMismatchAllow  MethodMismatchPolicy = "allow"
)
