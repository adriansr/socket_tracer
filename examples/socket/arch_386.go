package main

var archVariables = map[string]interface{}{
	// Regular function call parameters 1 to 6
	"P1":  "%ax",
	"P2":  "%dx",
	"P3":  "%cx",
	"P4":  "+4(%sp)",
	"P5":  "+8(%sp)",
	"P6":  "+12(%sp)",
	"RET": "%ax",
}
