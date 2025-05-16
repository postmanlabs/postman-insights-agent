package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

var numRuns uint64 = 0

func runChild(pwd string) (int, error) {
	numRuns += 1

	args := os.Args
	env := os.Environ()

	env = append(env, "__X_AKITA_CHILD=true")
	env = append(env, fmt.Sprintf("__X_AKITA_NUM_RUNS=%d", numRuns))

	pid, err := syscall.ForkExec(args[0], args, &syscall.ProcAttr{
		Dir: pwd,
		Env: env,
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return 0, err
	}

	return pid, nil
}

func collectStatus(pid int) (*os.ProcessState, error) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	return proc.Wait()
}

func runningInsideDocker() bool {
	return os.Getenv("__X_AKITA_CLI_DOCKER") == "true"
}

func isChildProcess() bool {
	return os.Getenv("__X_AKITA_CHILD") == "true"
}

func runSupervisor() error {
	if !runningInsideDocker() {
		return nil
	}

	if isChildProcess() {
		return nil
	}

	maxRuns, err := strconv.ParseUint(os.Getenv("__X_AKITA_MAX_RUNS"), 10, 64)
	if err != nil {
		maxRuns = 0
		printer.Debugf("unable to parse __X_AKITA_MAX_RUNS, using default value of 0 (no restriction)\n")
	}

	delay, err := strconv.ParseInt(os.Getenv("__X_AKITA_DELAY"), 10, 64)
	if err != nil {
		delay = 1
		printer.Debugf("unable to parse __X_AKITA_DELAY, using default value of 1\n")
	}

	if delay <= 0 {
		delay = 1
		printer.Debugf("__X_AKITA_DELAY must be greater than 0, using default value of 1\n")
	}

	pwd, err := os.Getwd()
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal)
	spawnSignal := make(chan bool)

	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGCHLD)

	printer.Debugf("starting the child process, run %d of %d\n", 1, maxRuns)

	pid, err := runChild(pwd)
	if err != nil {
		return err
	}

	for {
		select {
		case sig := <- sigs:
			sigNum, ok := sig.(syscall.Signal)
			if !ok {
				return fmt.Errorf("unable to process the signal %v\n", sig)
			}

			switch sigNum {
			case syscall.SIGINT, syscall.SIGTERM:
				if pid != 0 {
					printer.Debugf("sending %v to child\n", sigNum)

					err := syscall.Kill(pid, sigNum)
					if err != nil {
						return err
					}

					_, err = collectStatus(pid)
					if err != nil {
						return err
					}
				}

				syscall.Exit(128 + int(sigNum))

			case syscall.SIGCHLD:
				if pid == 0 {
					continue
				}

				status, err := collectStatus(pid)
				if err != nil {
					return err
				}

				printer.Debugf("child exited with %d\n", status.ExitCode())

				if status.ExitCode() >= 0 && status.ExitCode() < 126 {
					syscall.Exit(status.ExitCode())
				}

				pid = 0

				if numRuns == maxRuns {
					return fmt.Errorf("maximum number of runs reached (%d), bailing out", maxRuns)
				}

				printer.Debugf("retrying after %d seconds\n", delay)

				go func() {
					<- time.After(time.Duration(delay) * time.Second)
					spawnSignal <- true
				} ()
			}

		case <- spawnSignal:
			printer.Debugf("starting the child process, run %d of %d\n", numRuns + 1, maxRuns)

			pid, err = runChild(pwd)
			if err != nil {
				return err
			}
		}
	}

	// Unreachable
	panic("internal error")

	return nil
}
