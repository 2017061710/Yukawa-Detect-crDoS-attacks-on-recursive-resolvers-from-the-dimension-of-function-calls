//go:build ignore

package model

/*
#include "../ebpf/headers/bind/9_16_2/ebpf_model.h"
*/
import "C"

type Bind_9_16_2_Event_Kernel C.struct_hook_event
