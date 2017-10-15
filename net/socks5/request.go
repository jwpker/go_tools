package socks5

import (
	"io"
	"fmt"
	"net"
	"strings"
	"strconv"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)
const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

/**
SOCKS请求如下表所示：

　　+----+-----+-------+------+----------+----------+
　　|VER | CMD |　RSV　| ATYP | DST.ADDR | DST.PORT |
　　+----+-----+-------+------+----------+----------+
　　| 1　| 　1 | X'00' | 　1　| Variable |　　 2　　|
　　+----+-----+-------+------+----------+----------+

其中：
1. VER protocol version：X'05'
2. CMD
　2.1 CONNECT X'01'
　2.2 BIND X'02'
　2.3 UDP ASSOCIATE X'03'
3 RSV RESERVED 保留字段
4 ATYP address type of following address
　4.1 IP V4 address: X'01'
　4.2 DOMAINNAME: X'03'
　4.3 IP V6 address: X'04'
5 DST.ADDR desired destination address
6 DST.PORT desired destination port in network octet order
地址
在地址域(DST.ADDR,BND.ADDR)中，ATYP域详细说明了包含在该域内部的地址类型：
　　　　X'01'
该地址是IPv4地址，长4个八位组。
　　　　X'03'
该地址包含一个完全的域名。第一个八位组包含了后面名称的八位组的数目，没有中止的空八位组。
　　　　X'04'
该地址是IPv6地址，长16个八位组。
 */
type Request struct {
	Version uint8
	Command uint8
	DestAddr *NetAddr
	reader io.Reader
	writer io.Writer
}



func NewRequest(reader io.Reader,writer io.Writer) (*Request, error) {
	//读取version，cmd，RSV
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(reader, header, 3); err != nil {
		return nil, fmt.Errorf("Failed to get command version: %v", err)
	}

	if header[0] != sock5 {
		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}

	dest, err := readDestAddr(reader)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  sock5,
		Command:  header[1],
		DestAddr: dest,
		reader:  reader,
		writer: writer,
	}

	return request, nil
}

type NetAddr struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *NetAddr) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

func (a NetAddr) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}


func readDestAddr(r io.Reader) (*NetAddr, error) {
	netAddr := &NetAddr{}

	// 获取地址类型ATYP
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		netAddr.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		netAddr.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		netAddr.FQDN = string(fqdn)

	default:
		return nil, fmt.Errorf("Unrecognized address type")
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	netAddr.Port = (int(port[0]) << 8) | int(port[1])

	return netAddr, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request) error {
	// FQDN地址解析
	dest := req.DestAddr
	if dest.FQDN != "" {
		addr, err := net.ResolveIPAddr("ip", dest.FQDN)
		if err != nil {
			//send reply
			return err
		}
		dest.IP = addr.IP
	}

	// Switch on the command
	/*
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
	*/
	return s.handleConnect(req)
}

func (s *Server) handleConnect(req *Request) error {
	target, err := net.Dial("tcp", req.DestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(req.writer, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := NetAddr{IP: local.IP, Port: local.Port}
	if err := sendReply(req.writer, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.reader, errCh)
	go proxy(req.writer, target, errCh)
	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}



type closeWriter interface {
	CloseWrite() error
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
/**
　　到SOCKS服务器的连接一经建立，客户机即发送SOCKS请求信息，并且完成认证商
议。服务器评估请求，返回一个回应如下表所示：
　　+----+-----+-------+------+----------+----------+
　　|VER | REP |　RSV　| ATYP | BND.ADDR | BND.PORT |
　　+----+-----+-------+------+----------+----------+
　　| 1　|　1　| X'00' |　1 　| Variable | 　　2　　|
　　+----+-----+-------+------+----------+----------+

其中：

o VER protocol version: X'05'
o REP Reply field:
　　o X'00' succeeded
　　o X'01' general SOCKS server failure
　　o X'02' connection not allowed by ruleset
　　o X'03' Network unreachable
　　o X'04' Host unreachable
　　o X'05' Connection refused
　　o X'06' TTL expired
　　o X'07' Command not supported
　　o X'08' Address type not supported
　　o X'09' to X'FF' unassigned
o RSV RESERVED
o ATYP address type of following address
　　o IP V4 address: X'01'
　　o DOMAINNAME: X'03'
　　o IP V6 address: X'04'
o BND.ADDR server bound address
o BND.PORT server bound port in network octet order
标志RESERVED(RSV)的地方必须设置为X'00'。
 */

func sendReply(w io.Writer, resp uint8, addr *NetAddr) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = sock5
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}