package socks5

import "testing"

func TestConst(t *testing.T)  {
	t.Log(sock5)
}

func TestServer(t *testing.T)  {

	server,err:=New("127.0.0.1",9527)
	if err!=nil {
		t.Fail()
	}
	server.ListenAndServer()
	t.Log(sock5)
}


