package main

import "testing"

// Квота мест разводит стримы по релеям: пока на первом адресе нет места, выбор
// уходит на соседний, а не долбит переполненный
func TestPickStreamServerAddrPrefersARelayWithRoom(t *testing.T) {
	resetRelaySeats(t)
	setTURNServerQuota(2)

	addrs := []string{"a:19302", "b:19302"}
	seen := map[string]int{}
	for stream := range 4 {
		seen[pickStreamServerAddr(stream, addrs)]++
	}

	if seen["a:19302"] != 2 || seen["b:19302"] != 2 {
		t.Fatalf("места разъехались неровно: %v", seen)
	}
}

// Когда мест нет нигде, стрим всё равно получает адрес: отдать переполненный
// релей лучше, чем не отдать ничего
func TestPickStreamServerAddrFallsBackWhenEveryRelayIsFull(t *testing.T) {
	resetRelaySeats(t)
	setTURNServerQuota(1)

	addrs := []string{"a:19302", "b:19302"}
	for stream := range 2 {
		pickStreamServerAddr(stream, addrs)
	}

	if got := pickStreamServerAddr(99, addrs); got == "" {
		t.Fatal("третий стрим остался без адреса")
	}
}

// Место держит стрим, а не попытка: он умер - место свободно, и следующий стрим
// встаёт на тот же релей
func TestReleaseStreamSeatFreesTheRelay(t *testing.T) {
	resetRelaySeats(t)
	setTURNServerQuota(1)

	addrs := []string{"a:19302"}
	pickStreamServerAddr(0, addrs)
	if turnServerHasRoom("a:19302") {
		t.Fatal("занятое место всё ещё считается свободным")
	}

	releaseStreamSeat(0)
	if !turnServerHasRoom("a:19302") {
		t.Fatal("место не освободилось")
	}
}

// Повторный выбор того же адреса не считается вторым местом: иначе стрим,
// переподключившийся на свой релей, сам себя вытеснил бы с него
func TestClaimStreamSeatIsIdempotentForTheSameRelay(t *testing.T) {
	resetRelaySeats(t)
	setTURNServerQuota(1)

	claimStreamSeat(0, "a:19302")
	claimStreamSeat(0, "a:19302")
	releaseStreamSeat(0)

	if !turnServerHasRoom("a:19302") {
		t.Fatal("двойной учёт одного места")
	}
}

// Нулевая квота снимает лимит: на свой TURN можно вешать сколько влезет
func TestZeroQuotaMeansNoLimit(t *testing.T) {
	resetRelaySeats(t)
	setTURNServerQuota(0)

	for stream := range 50 {
		claimStreamSeat(stream, "own:3478")
	}
	if !turnServerHasRoom("own:3478") {
		t.Fatal("нулевая квота всё же ограничила релей")
	}
}

// resetRelaySeats чистит общий на процесс учёт мест и возвращает квоту по
// умолчанию после теста
func resetRelaySeats(t *testing.T) {
	t.Helper()
	turnServerSeats.Clear()
	streamSeatAddrs.Clear()
	turnServerCooldowns.Clear()
	streamServerOffsets.Clear()
	t.Cleanup(func() {
		turnServerSeats.Clear()
		streamSeatAddrs.Clear()
		turnServerCooldowns.Clear()
		streamServerOffsets.Clear()
		setTURNServerQuota(defaultTURNServerQuota)
	})
}
