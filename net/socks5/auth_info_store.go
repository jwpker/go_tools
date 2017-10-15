package socks5

type AuthInfoStore struct {
	data map[string]string
}

func (s *AuthInfoStore) Valid(user, password string) bool {
	pass,ok:= s.data[user]
	if !ok {
		return false
	}
	return password == pass
}

func (s *AuthInfoStore) Add(user, password string) bool {
	s.data[user]=password
	return true
}

func (s *AuthInfoStore) Del(user, password string) bool {
	if s.Valid(user,password){
		delete(s.data, user)
		return true
	}
	return false
}



func NewStaticAuthInfoStore() *AuthInfoStore {
	result:=new(AuthInfoStore)
	result.data=make(map[string]string)
	result.Add("admin","admin")
	return result
}




