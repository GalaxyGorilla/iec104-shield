// Command iec104peer is an independent IEC 60870-5-104 peer for the
// iec104-shield interop suite. It uses wendy512/iec104 (an independent Go
// implementation) as both outstation and master; neither end is the proxy's
// own protocol code.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/wendy512/go-iecp5/asdu"
	"github.com/wendy512/go-iecp5/cs104"
	"github.com/wendy512/iec104/client"
	"github.com/wendy512/iec104/server"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	host := flag.String("host", "127.0.0.1", "bind/connect host")
	port := flag.Int("port", 2404, "bind/connect port")
	commonAddr := flag.Uint("ca", 1, "common address")
	allowIOA := flag.Uint("allow-ioa", 1000, "allowed command IOA")
	denyIOA := flag.Uint("deny-ioa", 2000, "command IOA expected to be denied")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*host, *port, uint16(*commonAddr))
	case "client":
		runClient(*host, *port, uint16(*commonAddr), uint32(*allowIOA), uint32(*denyIOA))
	case "sbo-client":
		runSBOClient(*host, *port, uint16(*commonAddr), uint32(*allowIOA))
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runServer(host string, port int, ca uint16) {
	settings := server.NewSettings()
	settings.Host = host
	settings.Port = port
	settings.LogCfg = &server.LogCfg{Enable: false}
	srv := server.New(settings, &outstation{ca: ca})
	srv.SetOnConnectionHandler(func(conn asdu.Connect) {
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = asdu.Single(conn, false,
				asdu.CauseOfTransmission{Cause: asdu.Spontaneous},
				asdu.CommonAddr(ca),
				asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
		}()
	})
	srv.Start()
	time.Sleep(250 * time.Millisecond)
	fmt.Println("READY")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Stop()
}

type outstation struct{ ca uint16 }

func (o *outstation) OnInterrogation(conn asdu.Connect, pack *asdu.ASDU, _ asdu.QualifierOfInterrogation) error {
	fmt.Printf("INTERROGATION ca=%d\n", pack.CommonAddr)
	_ = pack.SendReplyMirror(conn, asdu.ActivationCon)
	_ = asdu.Single(conn, false, asdu.CauseOfTransmission{Cause: asdu.InterrogatedByStation},
		asdu.CommonAddr(o.ca), asdu.SinglePointInfo{Ioa: 100, Value: true, Qds: asdu.QDSGood})
	_ = pack.SendReplyMirror(conn, asdu.ActivationTerm)
	return nil
}

func (o *outstation) OnCounterInterrogation(asdu.Connect, *asdu.ASDU, asdu.QualifierCountCall) error {
	return nil
}
func (o *outstation) OnRead(asdu.Connect, *asdu.ASDU, asdu.InfoObjAddr) error { return nil }
func (o *outstation) OnClockSync(asdu.Connect, *asdu.ASDU, time.Time) error   { return nil }
func (o *outstation) OnResetProcess(asdu.Connect, *asdu.ASDU, asdu.QualifierOfResetProcessCmd) error {
	return nil
}
func (o *outstation) OnDelayAcquisition(asdu.Connect, *asdu.ASDU, uint16) error { return nil }
func (o *outstation) OnTestCommand(asdu.Connect, *asdu.ASDU) error              { return nil }

func (o *outstation) OnASDU(conn asdu.Connect, pack *asdu.ASDU) error {
	fmt.Printf("RX_COMMAND type=%d ca=%d\n", pack.Type, pack.CommonAddr)
	switch pack.Type {
	case asdu.C_SC_NA_1, asdu.C_DC_NA_1, asdu.C_RC_NA_1,
		asdu.C_SE_NA_1, asdu.C_SE_NB_1, asdu.C_SE_NC_1:
		// GetSingleCmd consumes the information object, so reply from a
		// clone rather than from the decoded packet.
		reply := pack.Clone()
		cmd := pack.GetSingleCmd()
		fmt.Printf("COMMAND type=%d ca=%d ioa=%d select=%t\n",
			pack.Type, pack.CommonAddr, cmd.Ioa, cmd.Qoc.InSelect)
		if err := reply.SendReplyMirror(conn, asdu.ActivationCon); err != nil {
			fmt.Printf("SEND_CON_ERROR %v\n", err)
		}
		if err := reply.SendReplyMirror(conn, asdu.ActivationTerm); err != nil {
			fmt.Printf("SEND_TERM_ERROR %v\n", err)
		}
	default:
		fmt.Printf("ASDU type=%d ca=%d\n", pack.Type, pack.CommonAddr)
	}
	return nil
}

func runClient(host string, port int, ca uint16, allowIOA, denyIOA uint32) {
	settings := client.NewSettings()
	settings.Host = host
	settings.Port = port
	settings.LogCfg = &client.LogCfg{Enable: false}
	call := &master{ca: ca, allowIOA: allowIOA, denyIOA: denyIOA}
	c := client.New(settings, call)
	var once sync.Once
	c.SetServerActiveHandler(func(c *client.Client) {
		once.Do(func() {
			fmt.Println("ACTIVE")
			if err := c.SendInterrogationCmd(ca); err != nil {
				fmt.Printf("SEND_ERROR interrogation: %v\n", err)
			}
			time.Sleep(300 * time.Millisecond)
			if err := c.SendCmd(ca, asdu.C_SC_NA_1, asdu.InfoObjAddr(allowIOA), true); err != nil {
				fmt.Printf("SEND_ERROR allow: %v\n", err)
			}
			time.Sleep(300 * time.Millisecond)
			if err := c.SendCmd(ca, asdu.C_SC_NA_1, asdu.InfoObjAddr(denyIOA), true); err != nil {
				fmt.Printf("SEND_ERROR deny: %v\n", err)
			}
			time.Sleep(1 * time.Second)
			fmt.Println("DONE")
			_ = c.Close()
		})
	})
	if err := c.Connect(); err != nil {
		fmt.Printf("CONNECT_ERROR %v\n", err)
		os.Exit(1)
	}
	time.Sleep(2500 * time.Millisecond)
}

type sboHandler struct{}

func (sboHandler) InterrogationHandler(asdu.Connect, *asdu.ASDU) error { return nil }
func (sboHandler) CounterInterrogationHandler(asdu.Connect, *asdu.ASDU) error {
	return nil
}
func (sboHandler) ReadHandler(asdu.Connect, *asdu.ASDU) error             { return nil }
func (sboHandler) TestCommandHandler(asdu.Connect, *asdu.ASDU) error      { return nil }
func (sboHandler) ClockSyncHandler(asdu.Connect, *asdu.ASDU) error        { return nil }
func (sboHandler) ResetProcessHandler(asdu.Connect, *asdu.ASDU) error     { return nil }
func (sboHandler) DelayAcquisitionHandler(asdu.Connect, *asdu.ASDU) error { return nil }
func (sboHandler) ASDUHandler(_ asdu.Connect, pack *asdu.ASDU) error {
	switch pack.Type {
	case asdu.C_SC_NA_1, asdu.C_DC_NA_1, asdu.C_RC_NA_1:
		cmd := pack.GetSingleCmd()
		fmt.Printf("COMMAND_RESPONSE type=%d ca=%d ioa=%d select=%t negative=%t\n",
			pack.Type, pack.CommonAddr, cmd.Ioa, cmd.Qoc.InSelect, pack.Coa.IsNegative)
	case asdu.M_SP_NA_1, asdu.M_SP_TB_1:
		for _, p := range pack.GetSinglePoint() {
			fmt.Printf("SINGLE_POINT ioa=%d value=%t cause=%d\n", p.Ioa, p.Value, pack.Coa.Cause)
		}
	default:
		fmt.Printf("ASDU type=%d ca=%d negative=%t\n", pack.Type, pack.CommonAddr, pack.Coa.IsNegative)
	}
	return nil
}

func runSBOClient(host string, port int, ca uint16, ioa uint32) {
	option := cs104.NewOption()
	if err := option.AddRemoteServer(fmt.Sprintf("%s:%d", host, port)); err != nil {
		fmt.Printf("OPTION_ERROR %v\n", err)
		os.Exit(1)
	}
	c := cs104.NewClient(&sboHandler{}, option)
	c.SetOnConnectHandler(func(c *cs104.Client) { c.SendStartDt() })
	c.SetServerActiveHandler(func(c *cs104.Client) {
		go func() {
			fmt.Println("ACTIVE")
			send := func(sel bool) {
				info := asdu.SingleCommandInfo{
					Ioa:   asdu.InfoObjAddr(ioa),
					Value: true,
					Qoc:   asdu.QualifierOfCommand{InSelect: sel},
				}
				if err := asdu.SingleCmd(c, asdu.C_SC_NA_1,
					asdu.CauseOfTransmission{Cause: asdu.Activation},
					asdu.CommonAddr(ca), info); err != nil {
					fmt.Printf("SEND_ERROR select=%t: %v\n", sel, err)
				}
			}
			send(true)
			time.Sleep(300 * time.Millisecond)
			send(false)
			time.Sleep(time.Second)
			fmt.Println("DONE")
			_ = c.Close()
		}()
	})
	if err := c.Start(); err != nil {
		fmt.Printf("CONNECT_ERROR %v\n", err)
		os.Exit(1)
	}
	time.Sleep(2500 * time.Millisecond)
}

type master struct {
	ca       uint16
	allowIOA uint32
	denyIOA  uint32
}

func (m *master) OnInterrogation(pack *asdu.ASDU) error {
	fmt.Printf("INTERROGATION_RESPONSE ca=%d\n", pack.CommonAddr)
	return nil
}
func (m *master) OnCounterInterrogation(*asdu.ASDU) error { return nil }
func (m *master) OnRead(*asdu.ASDU) error                 { return nil }
func (m *master) OnTestCommand(*asdu.ASDU) error          { return nil }
func (m *master) OnClockSync(*asdu.ASDU) error            { return nil }
func (m *master) OnResetProcess(*asdu.ASDU) error         { return nil }
func (m *master) OnDelayAcquisition(*asdu.ASDU) error     { return nil }

func (m *master) OnASDU(pack *asdu.ASDU) error {
	fmt.Printf("RX type=%d ca=%d negative=%t\n", pack.Type, pack.CommonAddr, pack.Coa.IsNegative)
	switch pack.Type {
	case asdu.M_SP_NA_1, asdu.M_SP_TB_1:
		for _, p := range pack.GetSinglePoint() {
			fmt.Printf("SINGLE_POINT ioa=%d value=%t cause=%d\n", p.Ioa, p.Value, pack.Coa.Cause)
		}
	case asdu.C_SC_NA_1, asdu.C_DC_NA_1, asdu.C_RC_NA_1,
		asdu.C_SE_NA_1, asdu.C_SE_NB_1, asdu.C_SE_NC_1:
		cmd := pack.GetSingleCmd()
		fmt.Printf("COMMAND_RESPONSE type=%d ca=%d ioa=%d negative=%t\n",
			pack.Type, pack.CommonAddr, cmd.Ioa, pack.Coa.IsNegative)
	default:
		fmt.Printf("ASDU type=%d ca=%d negative=%t\n", pack.Type, pack.CommonAddr, pack.Coa.IsNegative)
	}
	return nil
}
