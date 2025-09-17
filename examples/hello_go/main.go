//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type eventData struct {
	Uid  uint32
	Pid  uint32
	Comm [16]byte
}

func main() {

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}
	defer events.Close()

	// Open a perf reader from userspace into the perf event array
	// created earlier.
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		rd.Close()
	}()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.RawTracepoint,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R7, asm.R1), // Save the context pointer

			asm.LoadMem(asm.R6, asm.R1, 8, asm.Word), // r6 = ctx[1]
			asm.JNE.Imm(asm.R6, 59, "exit"),          // if r6 != 59, jump to exit

			// This part is executed only if the syscall is execve
			// Get the current UID and GID
			asm.FnGetCurrentUidGid.Call(),
			// Store the UID on the stack
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.Word),

			// Get the current PID
			asm.FnGetCurrentPidTgid.Call(),
			// Store the PID on the stack
			asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),

			// Get the current process name
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -16), // Buffer for the process name
			asm.Mov.Imm(asm.R2, 16),
			asm.FnGetCurrentComm.Call(),

			// Send the data to the perf event array
			asm.Mov.Reg(asm.R1, asm.R7), // Restore the context pointer
			asm.LoadMapPtr(asm.R2, events.FD()),
			asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
			asm.Mov.Reg(asm.R4, asm.RFP),
			asm.Add.Imm(asm.R4, -24), // Point to the start of the data
			asm.Mov.Imm(asm.R5, 24),  // Size of the data
			asm.FnPerfEventOutput.Call(),

			// set exit code to 0 and return
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),

			// exit label
			asm.Mov.Imm(asm.R0, 0).Sym("exit"),
			asm.Return(),
		},
	})
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: prog,
	})
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		var data eventData
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		log.Printf("execve called by UID: %d, PID: %d, Comm: %s", data.Uid, data.Pid, string(bytes.TrimRight(data.Comm[:], "\x00")))
	}
}