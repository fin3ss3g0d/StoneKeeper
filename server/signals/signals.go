// signals/signals.go
package signals

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func SetupSignalInterception() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT)

	go func() {
		for {
			select {
			case <-signals:
				fmt.Printf("\nPlease use the 'q', 'quit', or 'exit' command to properly shut down the program.\n> ")
			}
		}
	}()
}
