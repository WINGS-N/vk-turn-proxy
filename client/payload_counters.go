package main

import "sync/atomic"

// Счётчики полезной нагрузки, прошедшей через клиент.
//
// Нужны для расписок: клиент подписывает то, сколько реально получил, и это
// единственная цифра о трафике, которой можно верить. Считаются именно тут, а
// не по интерфейсу: интерфейсный счётчик тащит локальный DNS, keepalive и
// оверхед туннеля, и две стороны никогда не сойдутся, потому что считают разное.
//
// atomic, а не мьютекс: это горячий путь, по нему идёт каждый пакет
var (
	payloadUpBytes   atomic.Uint64
	payloadDownBytes atomic.Uint64
)

// countPayloadUp учитывает то, что ушло от нас наружу
func countPayloadUp(n int) {
	if n > 0 {
		payloadUpBytes.Add(uint64(n))
	}
}

// countPayloadDown учитывает то, что пришло к нам
func countPayloadDown(n int) {
	if n > 0 {
		payloadDownBytes.Add(uint64(n))
	}
}

// PayloadTotals отдаёт накопленное. Счётчики кумулятивные и не сбрасываются:
// дельту за окно считает тот, кто выписывает расписку, а сброс тут означал бы
// потерю трафика между двумя чтениями
func PayloadTotals() (up, down uint64) {
	return payloadUpBytes.Load(), payloadDownBytes.Load()
}
