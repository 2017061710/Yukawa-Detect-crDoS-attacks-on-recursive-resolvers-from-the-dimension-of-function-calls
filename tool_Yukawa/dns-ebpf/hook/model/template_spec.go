//go:build ignore

package model

/*
#include "../ebpf/headers/template/model.h"
*/
import "C"

type FuncEvent C.struct_hook_event
