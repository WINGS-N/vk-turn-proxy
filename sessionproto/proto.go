package sessionproto

import "google.golang.org/protobuf/proto"

func marshalProto(message proto.Message) ([]byte, error) {
	return proto.Marshal(message)
}

func unmarshalProto(payload []byte, message proto.Message) error {
	return proto.Unmarshal(payload, message)
}

func MarshalClientHello(hello *ClientHello) ([]byte, error) {
	return marshalProto(hello)
}

func MarshalServerHello(hello *ServerHello) ([]byte, error) {
	return marshalProto(hello)
}
