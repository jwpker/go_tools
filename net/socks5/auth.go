package socks5

import (
	"io"
	"fmt"
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)

	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

/***
  客户端连到服务器后，然后就发送请求来协商版本和认证方法：
  **客户端** 请求第一步
  +----+----------+----------+
  | VER|NMETHODS  | METHODS  |
  +----+----------+----------+
  | 1  |    1     | 1 - 255  |
  +----+----------+----------+
  VER 表示版本号:sock5 为 X'05'
  NMETHODS（方法选择）中包含在METHODS（方法）中出现的方法标识的数据（用字节表示）

  目前定义的METHOD有以下几种:
  X'00'  无需认证
  X'01'  通用安全服务应用程序(GSSAPI)
  X'02'  用户名/密码 auth (USERNAME/PASSWORD)
  X'03'- X'7F' IANA 分配(IANA ASSIGNED)
  X'80'- X'FE' 私人方法保留(RESERVED FOR PRIVATE METHODS)
  X'FF'  无可接受方法(NO ACCEPTABLE METHODS)

  **服务器** 响应第一步
  服务器从客户端发来的消息中选择一种方法作为返回
  服务器从METHODS给出的方法中选出一种，发送一个METHOD（方法）选择报文：
  +----+--------+
  |VER | METHOD |
  +----+--------+
  | 1　| 　1　 　|
  +----+--------+
 */
func (s *Server) authResponse(reader io.Reader,writer io.Writer) error  {
	// Read the version byte
	version := []byte{0}
	if _, err := reader.Read(version); err != nil {
		s.logger.Printf("[ERR] socks: Failed to get version byte: %v. ", err)
		return err
	}

	if version[0]!=sock5{
		err := fmt.Errorf("Unsupported SOCKS version: %v. ", version)
		s.logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Read methods
	header := []byte{0}
	if _, err := reader.Read(header); err != nil {
		return err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(reader, methods, numMethods); err!=nil{
		return err
	}
	var result Authenticator=nil
	if s.isAuth {
		flag:=false
		for _, method := range methods {
			if method==UserPassAuth{
				result=new(UserPassAuthenticator)
				flag=true
			}
		}
		if !flag{
			result=new(NoAcceptableAuthenticator)
		}
	}else{
		result=new(NoAuthAuthenticator)
	}
	return result.Authenticate(reader,writer)
}

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) error
	GetCode() uint8
}

type NoAcceptableAuthenticator struct{}

func (a NoAcceptableAuthenticator) GetCode() uint8 {
	return noAcceptable
}

func (a NoAcceptableAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{sock5, noAcceptable})
	return err
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{sock5, NoAuth})
	return err
}
type UserPassAuthenticator struct {
	authInfo *AuthInfoStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	if _, err := writer.Write([]byte{sock5, UserPassAuth}); err != nil {
		return err
	}

	// 取得认证版本和用户名长度
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return err
	}

	if header[0] != userAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	//获取用户名
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return err
	}

	// 获取密码长度
	if _, err := reader.Read(header[:1]); err != nil {
		return err
	}

	// 获取密码
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return err
	}

	a.authInfo=NewStaticAuthInfoStore()
	// 验证用户名密码
	if a.authInfo.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
	}
	return nil
}

