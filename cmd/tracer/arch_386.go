package main

var archVariables = map[string]interface{}{
	// Regular function call parameters 1 to 6
	// This calling convention is used internally by the kernel
	// which is built by default with (-mregparam=3)
	"P1":  "%ax",
	"P2":  "%dx",
	"P3":  "%cx",
	"P4":  "+4(%sp)",
	"P5":  "+8(%sp)",
	"P6":  "+12(%sp)",
	"RET": "%ax",

	// Exported function call parameters are not optimized with mregparam and
	// all parameters are passed in the stack.
	"EP1": "+4(%sp)",
	"EP2": "+8(%sp)",
	"EP3": "+12(%sp)",
	"EP4": "+16(%sp)",
	"EP5": "+20(%sp)",
	"EP6": "+24(%sp)",
}
