package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/xtaci/smux"
)

func handleTCPConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) error {
	kcpSession, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		return fmt.Errorf("KCP session error: %w", err)
	}
	defer func() {
		if closeErr := kcpSession.Close(); closeErr != nil {
			log.Printf("failed to close KCP session: %v", closeErr)
		}
	}()

	smuxSession, err := smux.Server(kcpSession, tcputil.DefaultSmuxConfig())
	if err != nil {
		return fmt.Errorf("smux server error: %w", err)
	}
	defer func() {
		if closeErr := smuxSession.Close(); closeErr != nil {
			log.Printf("failed to close smux session: %v", closeErr)
		}
	}()

	var waitGroup sync.WaitGroup
	for {
		stream, err := smuxSession.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
				waitGroup.Wait()
				return nil
			default:
			}
			if smuxSession.IsClosed() {
				waitGroup.Wait()
				return nil
			}
			waitGroup.Wait()
			return fmt.Errorf("smux accept error: %w", err)
		}

		waitGroup.Add(1)
		go func(smuxStream *smux.Stream) {
			defer waitGroup.Done()
			defer func() {
				if closeErr := smuxStream.Close(); closeErr != nil && closeErr != smux.ErrGoAway {
					log.Printf("failed to close smux stream: %v", closeErr)
				}
			}()

			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if closeErr := backendConn.Close(); closeErr != nil {
					log.Printf("failed to close backend connection: %v", closeErr)
				}
			}()

			pipeTCPConns(ctx, smuxStream, backendConn)
		}(stream)
	}
}

func pipeTCPConns(ctx context.Context, first net.Conn, second net.Conn) {
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(copyCtx, func() {
		_ = first.SetDeadline(time.Now())
		_ = second.SetDeadline(time.Now())
	})

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)

	go func() {
		defer waitGroup.Done()
		if _, err := io.Copy(first, second); err != nil {
			log.Printf("pipeTCPConns: copy first<-second error: %v", err)
		}
	}()

	go func() {
		defer waitGroup.Done()
		if _, err := io.Copy(second, first); err != nil {
			log.Printf("pipeTCPConns: copy second<-first error: %v", err)
		}
	}()

	waitGroup.Wait()
	_ = first.SetDeadline(time.Time{})
	_ = second.SetDeadline(time.Time{})
}
