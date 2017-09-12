package main

type Message struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (self *Message) String() string {
	return self.Type + ": " + self.Message
}
