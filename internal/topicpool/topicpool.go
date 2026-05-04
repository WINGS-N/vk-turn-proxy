// Package topicpool provides a rotating set of LiveKit DataPacket topic strings
// designed to look like a mix of legitimate VK Calls signalling/media channels.
// Picking a fresh topic per outbound packet hides the otherwise-identifiable
// "vk-turn-proxy/wbstream" string from any operator-side metadata inspection.
package topicpool

import "math/rand"

// weightedTopic pairs a topic name with the relative frequency it should be
// picked. Audio/video carry by far the largest share of a real VK Calls
// participant's DataPacket traffic, so they must dominate the distribution —
// a perfectly uniform mix of "presence/typing" and "audio/opus" would itself
// be a fingerprint.
type weightedTopic struct {
	name   string
	weight int
}

var topics = []weightedTopic{
	{"audio/opus", 24},
	{"audio/levels", 8},
	{"video/vp8", 18},
	{"video/h264", 18},
	{"video/preview", 6},
	{"screen-share/preview", 3},
	{"screen-share/cursor", 2},
	{"presence/typing", 1},
	{"presence/state", 2},
	{"events/state-sync", 4},
	{"events/notifications", 2},
	{"metrics/rtc-stats", 5},
	{"data/file-transfer", 1},
	{"data/chat-messages", 2},
	{"control/heartbeat", 4},
}

var (
	cumulative  []int
	totalWeight int
)

func init() {
	cumulative = make([]int, len(topics))
	sum := 0
	for i, t := range topics {
		sum += t.weight
		cumulative[i] = sum
	}
	totalWeight = sum
}

// Pick returns a randomly-selected topic, weighted toward media channels.
func Pick() string {
	r := rand.Intn(totalWeight)
	for i, c := range cumulative {
		if r < c {
			return topics[i].name
		}
	}
	return topics[len(topics)-1].name
}

// All returns the current pool names (read-only) for diagnostics or testing.
func All() []string {
	out := make([]string, len(topics))
	for i, t := range topics {
		out[i] = t.name
	}
	return out
}
