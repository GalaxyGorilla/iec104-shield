// Command iec104peer2 is a second, independent IEC 60870-5-104 peer for the
// interop suite. It uses otfabric/go-iec104, a different stack from the
// wendy512/iec104 peer in ../iec104peer, so a passing run is not just the
// proxy talking to one library's quirks.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
	"github.com/otfabric/go-iec104/server"
)

func main() {
	mode := flag.String("mode", "server", "server, client or sbo-client")
	host := flag.String("host", "127.0.0.1", "bind/connect host")
	port := flag.Int("port", 2404, "bind/connect port")
	commonAddr := flag.Uint("ca", 1, "common address")
	allowIOA := flag.Uint("allow-ioa", 1000, "allowed command IOA")
	denyIOA := flag.Uint("deny-ioa", 2000, "command IOA expected to be denied")
	flag.Parse()

	ca := uint16(*commonAddr)
	switch *mode {
	case "server":
		runServer(*host, *port, ca)
	case "client":
		runClient(*host, *port, ca, uint32(*allowIOA), uint32(*denyIOA))
	case "sbo-client":
		runSBOClient(*host, *port, ca, uint32(*allowIOA))
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runServer(host string, port int, ca uint16) {
	mux := server.NewMux()
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		fmt.Printf("INTERROGATION ca=%d\n", req.CommonAddr)
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr,
			asdu.SinglePoint{IOA: 100, Value: true}))
		_ = s.Terminate(req)
	})
	mux.HandleFunc(asdu.C_SC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		cmd, ok := req.First().(asdu.SingleCommand)
		if !ok {
			_ = s.Reject(req, asdu.CauseUnknownType)
			return
		}
		fmt.Printf("COMMAND type=%d ca=%d ioa=%d select=%t\n",
			req.Type, req.CommonAddr, cmd.IOA, cmd.Select)
		_ = s.Confirm(req)
		_ = s.Terminate(req)
	})

	srv, err := server.New(mux,
		server.WithCommonAddrs(asdu.CommonAddr(ca)),
		server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
			if state != iec104.StateStarted {
				return
			}
			go func() {
				time.Sleep(500 * time.Millisecond)
				_ = s.Send(s.Context(), asdu.New(asdu.CauseSpontaneous, asdu.CommonAddr(ca),
					asdu.SinglePoint{IOA: 100, Value: true}))
			}()
		}))
	if err != nil {
		fmt.Printf("SERVER_ERROR %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("LISTEN_ERROR %v\n", err)
		os.Exit(1)
	}
	fmt.Println("READY")
	go func() { _ = srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = srv.Close()
}

func printASDU(a *asdu.ASDU) {
	switch a.Type {
	case asdu.M_SP_NA_1, asdu.M_SP_TB_1:
		for _, obj := range a.Objects {
			p, ok := obj.(asdu.SinglePoint)
			if !ok {
				continue
			}
			fmt.Printf("SINGLE_POINT ioa=%d value=%t cause=%d\n", p.IOA, p.Value, a.Cause)
		}
	case asdu.C_SC_NA_1, asdu.C_SC_TA_1:
		for _, obj := range a.Objects {
			cmd, ok := obj.(asdu.SingleCommand)
			if !ok {
				continue
			}
			fmt.Printf("COMMAND_RESPONSE type=%d ca=%d ioa=%d select=%t negative=%t\n",
				a.Type, a.CommonAddr, cmd.IOA, cmd.Select, a.Negative)
		}
	default:
		fmt.Printf("ASDU type=%d ca=%d negative=%t\n", a.Type, a.CommonAddr, a.Negative)
	}
}

func dial(host string, port int) (*client.Client, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c, err := client.Dial(ctx, fmt.Sprintf("%s:%d", host, port),
		client.WithHandler(client.HandlerFunc(printASDU)))
	if err != nil {
		fmt.Printf("CONNECT_ERROR %v\n", err)
		cancel()
		os.Exit(1)
	}
	return c, ctx, cancel
}

func runClient(host string, port int, ca uint16, allowIOA, denyIOA uint32) {
	c, ctx, cancel := dial(host, port)
	defer cancel()
	defer c.Close()

	fmt.Println("ACTIVE")
	if _, err := c.Interrogate(ctx, asdu.CommonAddr(ca), asdu.QOIStation); err != nil {
		fmt.Printf("SEND_ERROR interrogation: %v\n", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := c.Command(ctx, asdu.CommonAddr(ca), asdu.SingleCommand{
		IOA: asdu.IOA(allowIOA), Value: true,
	}); err != nil {
		fmt.Printf("COMMAND_ERROR allow: %v\n", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := c.Command(ctx, asdu.CommonAddr(ca), asdu.SingleCommand{
		IOA: asdu.IOA(denyIOA), Value: true,
	}); err != nil {
		fmt.Printf("COMMAND_ERROR deny: %v\n", err)
	}
	time.Sleep(1500 * time.Millisecond)
	fmt.Println("DONE")
}

func runSBOClient(host string, port int, ca uint16, ioa uint32) {
	c, ctx, cancel := dial(host, port)
	defer cancel()
	defer c.Close()

	fmt.Println("ACTIVE")
	for _, selectBit := range []bool{true, false} {
		if err := c.Command(ctx, asdu.CommonAddr(ca), asdu.SingleCommand{
			IOA: asdu.IOA(ioa), Value: true, Select: selectBit,
		}); err != nil {
			fmt.Printf("COMMAND_ERROR select=%t: %v\n", selectBit, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	time.Sleep(time.Second)
	fmt.Println("DONE")
}
