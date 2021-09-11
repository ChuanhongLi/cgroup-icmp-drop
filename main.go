package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

const (
	bfpCodePath = "out/ebpf.o"
	cgroupPath = "/mnt/cgroup2"
)

type Connection struct {
	sip uint32
	dip uint32
} 

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
		os.Exit(1)
	}

	//fileName := os.Args[1]
	//b := elf.NewModule(fileName)
	b := elf.NewModule(bfpCodePath)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}
	
	err := b.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	//os.Args[2]
	for cgProg := range b.IterCgroupProgram() {
		if err := elf.AttachCgroupProgram(cgProg, cgroupPath, elf.EgressType); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
	
	fmt.Println("Ready.")
	
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	go func() {
		<-sigs
		for cgProg := range b.IterCgroupProgram() {
			if err := elf.DetachCgroupProgram(cgProg, cgroupPath, elf.EgressType); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Stop filter\n")
			os.Exit(0)
		}
	}()
	
	mp := b.Map("block_map")
	
	var lookup_key, next_key, value Connection
	lookup_key = Connection{0,0}
	
	for {
		//fmt.Printf("The block icmp session :\n")
		for {
				flag, err := b.LookupNextElement(mp, unsafe.Pointer(&lookup_key), unsafe.Pointer(&next_key), unsafe.Pointer(&value))
				if flag == true {
					fmt.Printf("Ping from %3d.%3d.%3d.%3d  to %3d.%3d.%3d.%3d is blocked\n",
						(next_key.sip & 0xFF), ((next_key.sip >> 8)& 0xFF),((next_key.sip >> 16)& 0xFF),((next_key.sip >> 24)& 0xFF),			
						(next_key.dip & 0xFF), ((next_key.dip >> 8)& 0xFF),((next_key.dip >> 16)& 0xFF),((next_key.dip >> 24)& 0xFF))
				}
				if flag == false {
					if err != nil {
						panic(err)
					}
					//fmt.Println(flag)
					break
				}
				lookup_key = next_key
		}
		fmt.Println()
		time.Sleep(1000 * time.Millisecond)
		lookup_key = Connection{0,0}
	}
}
