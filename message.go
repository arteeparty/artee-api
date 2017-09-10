package main

type Message struct {
	id      int
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (self *Message) String() string {
	return self.Type + ": " + self.Message
}
