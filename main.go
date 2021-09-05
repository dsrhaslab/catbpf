package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/taniaesteves/catbpf/tracer"
)

func waitSig(c <-chan os.Signal, sig os.Signal, all bool) {
	// Sleep multiple times to give the kernel more tries to
	// deliver the signal.
	for i := 0; i < 10; i++ {
		select {
		case s := <-c:
			if all && s == syscall.SIGURG {
				continue
			}
			if s != sig {
				log.Printf("signal was %v, want %v\n", s, sig)
			}
			return

		case <-time.After(1500 * time.Millisecond):
		}
	}
	log.Fatalf("timeout waiting for %v\n", sig)
}

func PrepareTracer(childPID int, whitelistfile string, stats bool, text bool) (*tracer.Tracer, error) {
	log.Printf("Running tracer for pid %d", childPID)

	resourcesBox, err := rice.FindBox("catbpf_resources")
	if err != nil {
		log.Fatal(err)
	}
	structs, err := resourcesBox.String("bpfprogram.h")
	if err != nil {
		log.Fatal(err)
	}
	bpfProgram, err := resourcesBox.String("bpfprogram.c")
	if err != nil {
		log.Fatal(err)
	}
	bpfProgram = strings.Replace(bpfProgram, "//HEADER_CONTENT//", structs, -1)

	// Read whitelist file
	var whitelist []string
	if whitelistfile != "" {
		whitelistf, err := os.Open(whitelistfile)
		if err != nil {
			log.Fatal(err)
		}
		defer whitelistf.Close()
		scanner := bufio.NewScanner(whitelistf)

		for scanner.Scan() {
			whitelist = append(whitelist, scanner.Text())
		}
		log.Println("Whitelist:", whitelist)
	}

	// Init tracer
	btracer, err := tracer.InitTracer(bpfProgram, childPID, 65536, whitelist, stats, text)
	return btracer, nil

}

func main() {

	whitelistfile := flag.String("whitelist", "", "White list file name.")
	stats := flag.Bool("stats", false, "Print events stats.")
	text := flag.Bool("text", false, "Save data as text. Default saves only signatures.")
	pid := flag.Int("pid", -1, "Filter events of the given PID.")
	log2file := flag.Bool("log2file", false, "Log CatBpf output to file")
	consumers := flag.Int("c", 2, "Number of consumers")
	flag.Parse()
	args := flag.Args()

	tracerStartTime := time.Now()

	if *log2file {
		logFile, err := os.OpenFile("catbpf.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer logFile.Close()

		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	if *pid != -1 {
		// ----- PREPARE TRACER -----

		btracer, err := PrepareTracer(*pid, *whitelistfile, *stats, *text)
		if err != nil {
			log.Fatalf("An error occurred while preparing tracer: %v\n", err)
		}
		// ----- START TRACER -----

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, os.Kill)

		for i := 0; i < *consumers; i++ {
			go btracer.RunConsumer()
		}

		btracer.Exit = true
		btracer.Run()
		log.Printf("%v consumers waiting for events...\n", *consumers)
		start := time.Now()
		<-sig
		elapsed := time.Since(start)
		log.Printf("Program Execution Time was %d ms\n", elapsed.Milliseconds())
		btracer.PrintStats()

		btracer.Stop()

		btracer.Close()

		tracerTime := time.Since(tracerStartTime)
		log.Printf("Tracer Execution Time was %d ms\n", tracerTime.Milliseconds())
		os.Exit(0)
	}

	// ----- LAUNCH THE TARGET PROGRAM AND WAIT -----

	if _, isChild := os.LookupEnv("CHILD_ID"); !isChild {
		args := append(os.Args, fmt.Sprintf("#child_%d", 1))
		childENV := []string{
			fmt.Sprintf("CHILD_ID=1"),
		}
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("getwd err: %s", err)
		}
		childPID, _ := syscall.ForkExec(args[0], args, &syscall.ProcAttr{
			Dir: pwd,
			Env: append(os.Environ(), childENV...),
			Sys: &syscall.SysProcAttr{
				Setsid: true,
			},
			Files: []uintptr{0, 1, 2},
		})

		// ----- PREPARE TRACER -----

		btracer, err := PrepareTracer(childPID, *whitelistfile, *stats, *text)
		if err != nil {
			log.Fatalf("An error occurred while preparing tracer: %v\n", err)
		}

		// ----- START TRACER -----

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGCHLD)

		for i := 0; i < *consumers; i++ {
			go btracer.RunConsumer()
		}

		btracer.Run()
		log.Printf("%v consumers waiting for events...\n", *consumers)
		start := time.Now()
		syscall.Kill(childPID, syscall.SIGCONT)
		s := <-sig
		if s == os.Interrupt || s == os.Kill {
			syscall.Kill(childPID, syscall.SIGKILL)
		}

		elapsed := time.Since(start)
		log.Printf("Program Execution Time was %d ms\n", elapsed.Milliseconds())
		btracer.PrintStats()

		btracer.Stop()

		btracer.Close()

		tracerTime := time.Since(tracerStartTime)
		log.Printf("Tracer Execution Time was %d ms\n", tracerTime.Milliseconds())
		os.Exit(0)

	} else { // Target process
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGCONT)
		defer signal.Stop(c)
		waitSig(c, syscall.SIGCONT, false)

		var cmdArgs = args[0 : len(args)-1]
		var cmdName = args[0]

		log.Printf("Command is: %v\n", cmdArgs)
		err := syscall.Exec(cmdName, cmdArgs, os.Environ())
		log.Println(err)
	}

}
