// Package wbstream implements WB Stream (LiveKit-on-wb.ru) transport for vk-turn-proxy.
//
// Two layers live here:
//
//   - api.go — HTTP calls to stream.wb.ru: guest-register, room create/join, room token.
//   - peer.go — LiveKit-room peer wrapper (DataPacket send/receive, lifecycle).
//
// The package is consumed by both client and server when -mode wb-stream is selected.
// Server-side typically calls AcquireRoomToken with a known room_id received via
// CLIENT_HELLO_TYPE_ROOM_EXCHANGE, while the client either creates a fresh room or
// joins one supplied by the user.
package wbstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	apiBase   = "https://stream.wb.ru"
	userAgent = "vk-turn-proxy/wbstream"
	// LiveKitWSSURL is the SFU endpoint that hosts wb.ru rooms.
	LiveKitWSSURL = "wss://wbstream01-el.wb.ru:7880"
)

var (
	errGuestRegister = errors.New("guest register failed")
	errCreateRoom    = errors.New("create room failed")
	errJoinRoom      = errors.New("join room failed")
	errGetToken      = errors.New("get token failed")
)

type guestRegisterRequest struct {
	DisplayName string `json:"displayName"`
	Device      device `json:"device"`
}

type device struct {
	DeviceName string `json:"deviceName"`
	DeviceType string `json:"deviceType"`
}

type guestRegisterResponse struct {
	AccessToken string `json:"accessToken"`
}

type createRoomRequest struct {
	RoomType    string `json:"roomType"`
	RoomPrivacy string `json:"roomPrivacy"`
}

type createRoomResponse struct {
	RoomID string `json:"roomId"`
}

type tokenResponse struct {
	RoomToken string `json:"roomToken"`
}

func newClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// RegisterGuest exchanges a display name for a short-lived guest access token.
func RegisterGuest(ctx context.Context, displayName string) (string, error) {
	body, err := json.Marshal(guestRegisterRequest{
		DisplayName: displayName,
		Device: device{
			DeviceName: "Linux",
			DeviceType: "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP",
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/auth/api/v1/auth/user/guest-register", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := newClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: %d %s", errGuestRegister, resp.StatusCode, raw)
	}

	var out guestRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return out.AccessToken, nil
}

// CreateRoom creates a new free room and returns its identifier.
func CreateRoom(ctx context.Context, accessToken string) (string, error) {
	body, err := json.Marshal(createRoomRequest{
		RoomType:    "ROOM_TYPE_ALL_ON_SCREEN",
		RoomPrivacy: "ROOM_PRIVACY_FREE",
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api-room/api/v2/room", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)

	resp, err := newClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: %d %s", errCreateRoom, resp.StatusCode, raw)
	}

	var out createRoomResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return out.RoomID, nil
}

// JoinRoom registers the guest as a participant of the supplied room.
func JoinRoom(ctx context.Context, accessToken, roomID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api-room/api/v1/room/%s/join", apiBase, url.PathEscape(roomID)),
		bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)

	resp, err := newClient().Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: %d %s", errJoinRoom, resp.StatusCode, raw)
	}
	return nil
}

// GetRoomToken returns a LiveKit JWT for connecting to the SFU.
func GetRoomToken(ctx context.Context, accessToken, roomID, displayName string) (string, error) {
	endpoint := fmt.Sprintf("%s/api-room-manager/api/v1/room/%s/token", apiBase, url.PathEscape(roomID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	q := req.URL.Query()
	q.Add("deviceType", "PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP")
	q.Add("displayName", displayName)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userAgent)

	resp, err := newClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: %d %s", errGetToken, resp.StatusCode, raw)
	}

	var out tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return out.RoomToken, nil
}

// AcquireRoomToken does the full handshake (guest-register → maybe create-room → join → get-token)
// and returns the room ID actually used and the LiveKit JWT for it.
func AcquireRoomToken(ctx context.Context, displayName, requestedRoomID string) (roomID, roomToken string, err error) {
	accessToken, err := RegisterGuest(ctx, displayName)
	if err != nil {
		return "", "", fmt.Errorf("register guest: %w", err)
	}

	roomID = requestedRoomID
	if roomID == "" || roomID == "any" {
		roomID, err = CreateRoom(ctx, accessToken)
		if err != nil {
			return "", "", fmt.Errorf("create room: %w", err)
		}
	}

	if err := JoinRoom(ctx, accessToken, roomID); err != nil {
		return "", "", fmt.Errorf("join room: %w", err)
	}
	roomToken, err = GetRoomToken(ctx, accessToken, roomID, displayName)
	if err != nil {
		return "", "", fmt.Errorf("get token: %w", err)
	}
	return roomID, roomToken, nil
}
