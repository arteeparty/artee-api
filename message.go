package main

// Message is a websocket message
type Message struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (m *Message) String() string {
	return m.Type + ": " + m.Message
}
