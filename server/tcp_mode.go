package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/xtaci/smux"
)

func handleTCPConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string, flavor sessionproto.TcpTransportFlavor) error {
	smuxSession, cleanup, err := openTCPSmuxServer(dtlsConn, flavor)
	if err != nil {
		return err
	}
	defer cleanup()

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

func openTCPSmuxServer(dtlsConn net.Conn, _ sessionproto.TcpTransportFlavor) (*smux.Session, func(), error) {
	// Always KCP+smux. DIRECT_SMUX (smux directly over the datagram DTLS conn) was removed:
	// it tripped pion/dtls "buffer is too small" on smux's sub-record reads. KCP supplies the
	// reliable ordered stream smux needs. Matches the reference upstream (Moroka8).
	kcpSession, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		return nil, nil, fmt.Errorf("KCP session error: %w", err)
	}
	smuxSession, err := smux.Server(kcpSession, tcputil.DefaultSmuxConfig())
	if err != nil {
		_ = kcpSession.Close()
		return nil, nil, fmt.Errorf("smux server error: %w", err)
	}
	log.Printf("TCP server session ready (transport flavor: legacy KCP+smux)")
	return smuxSession, func() {
		if closeErr := smuxSession.Close(); closeErr != nil {
			log.Printf("failed to close smux session: %v", closeErr)
		}
		if closeErr := kcpSession.Close(); closeErr != nil {
			log.Printf("failed to close KCP session: %v", closeErr)
		}
	}, nil
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
