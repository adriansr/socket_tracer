package main

var archVariables = map[string]interface{}{
	// Regular function call parameters 1 to 6
	"P1": "%di",
	"P2": "%si",
	"P3": "%dx",
	"P4": "%cx",
	"P5": "%r8",
	"P6": "%r9",

	// Exported function call parameters
	"EP1": "%di",
	"EP2": "%si",
	"EP3": "%dx",
	"EP4": "%cx",
	"EP5": "%r8",
	"EP6": "%r9",

	"RET": "%ax",
}
