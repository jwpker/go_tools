package socks5

import (
	"log"
	"os"
	"net"
	"strconv"
	"bufio"
)

type mysql string

const (
	sock5=uint8(5)
)

type Server struct{
	addr string
	port int
	isAuth bool
	logger *log.Logger
}

func New(addr string,port int) (*Server,error)  {
	server := &Server{
		addr: addr,
		port:port,
		isAuth:false,
		logger:log.New(os.Stdout, "", log.LstdFlags),
	}
	return server,nil
}

func (s *Server)ListenAndServer() error {
	l,error:=net.Listen("tcp4",s.addr+":"+strconv.Itoa(s.port))
	if error!=nil {
		return error
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.connHandle(conn)
	}
	return nil
}

func (s *Server)connHandle(conn net.Conn) error {
	defer conn.Close()
	readerBuf := bufio.NewReader(conn)

	// 权限验证
	err:=s.authResponse(readerBuf,conn)
	if(err!=nil){
		return err
	}

	request, err := NewRequest(readerBuf,conn)
	if err != nil {
		return err
	}

	err = s.handleRequest(request)
	if err != nil {
		return err
	}

	return nil
}
