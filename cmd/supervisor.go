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

func runChild(pwd string, numRuns uint64) (int, uint64, error) {
	numRuns += 1

	args := os.Args
	env := os.Environ()

	env = append(env, "__X_AKITA_NO_FORK=1")
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
		return 0, 0, err
	}

	return pid, numRuns, nil
}

func collectStatus(pid int) (*os.ProcessState, error) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	return proc.Wait()
}

func runSupervisor() error {
	e := os.Getenv("__X_AKITA_NO_FORK")

	if e == "1" {
		return nil
	}

	maxRuns, err := strconv.ParseUint(os.Getenv("__X_AKITA_MAX_RUNS"), 10, 64)
	if err != nil {
		maxRuns = 0
		printer.Warningln("unable to parse __X_AKITA_MAX_RUNS, using default value of 0 (no restriction)")
	}

	delay, err := strconv.ParseUint(os.Getenv("__X_AKITA_DELAY"), 10, 64)
	if err != nil {
		delay = 1
		printer.Warningln("unable to parse __X_AKITA_DELAY, using default value of 1")
	}

	pwd, err := os.Getwd()
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGCHLD)

	printer.Infof("starting the child process, run %d of %d", 1, maxRuns)

	pid, numRuns, err := runChild(pwd, 0)
	if err != nil {
		return err
	}

	for {
		sig := <- sigs

		if sig.(syscall.Signal) == syscall.SIGINT || sig.(syscall.Signal) == syscall.SIGTERM {
			if pid != 0 {
				printer.Infof("sending %s to child", sig.(syscall.Signal))

				syscall.Kill(pid, sig.(syscall.Signal))

				status, err := collectStatus(pid)
				if err != nil {
					return err
				}

				syscall.Exit(status.ExitCode())
			}

			break
		}

		if sig.(syscall.Signal) == syscall.SIGCHLD {
			status, err := collectStatus(pid)
			if err != nil {
				return err
			}

			printer.Infof("child exited with %d", status.ExitCode())

			if status.Success() {
				break
			}

			pid = 0

			if numRuns == maxRuns {
				return fmt.Errorf("maximum number of runs reached (%d), bailing out", maxRuns)
			}

			printer.Errorf("retrying after %d seconds", delay)

			go func() {
				<- time.After(time.Duration(int(delay)) * time.Second)
				sigs <- syscall.SIGALRM
			} ()
		}

		if sig.(syscall.Signal) == syscall.SIGALRM {
			printer.Infof("starting the child process, run %d of %d", numRuns + 1, maxRuns)

			pid, numRuns, err = runChild(pwd, numRuns)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
