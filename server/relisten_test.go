package main

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func fakeGen(addr string, closed *sync.Map) *listenGen {
	return &listenGen{addr: addr, close: func() { closed.Store(addr, true) }}
}

func TestDataPlaneMovesAndDrainsTheOldSocket(t *testing.T) {
	var closed sync.Map
	served := make(chan string, 4)
	d := newDataPlane()
	d.setOpen(func(addr string) (*listenGen, error) { return fakeGen(addr, &closed), nil })
	d.setServe(func(gen *listenGen) { served <- gen.addr })

	if _, err := d.Start("0.0.0.0:56000"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if d.Addr() != "0.0.0.0:56000" {
		t.Fatalf("слушаем %q", d.Addr())
	}

	moved, err := d.Relisten("0.0.0.0:41337", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("relisten: %v", err)
	}
	if moved != "0.0.0.0:41337" || d.Addr() != "0.0.0.0:41337" {
		t.Fatalf("переехали на %q, а Addr отдаёт %q", moved, d.Addr())
	}
	select {
	case addr := <-served:
		if addr != "0.0.0.0:41337" {
			t.Fatalf("акцептор поднят на %q", addr)
		}
	case <-time.After(time.Second):
		t.Fatal("новый сокет никто не обслуживает")
	}
	// Прежний сокет обязан пережить сам вызов: его сессии ещё живы
	if _, gone := closed.Load("0.0.0.0:56000"); gone {
		t.Fatal("старый сокет закрыт сразу, а не после дренажа")
	}
	deadline := time.After(2 * time.Second)
	for {
		if _, gone := closed.Load("0.0.0.0:56000"); gone {
			break
		}
		select {
		case <-deadline:
			t.Fatal("старый сокет так и не закрылся после дренажа")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// Занятый порт оставляет релей там, где он был: уйти в темноту хуже, чем отказать
func TestDataPlaneKeepsServingWhenTheNewPortIsTaken(t *testing.T) {
	var closed sync.Map
	d := newDataPlane()
	d.setOpen(func(addr string) (*listenGen, error) {
		if strings.HasSuffix(addr, ":80") {
			return nil, errors.New("address already in use")
		}
		return fakeGen(addr, &closed), nil
	})
	d.setServe(func(*listenGen) {})
	if _, err := d.Start("0.0.0.0:56000"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := d.Relisten("0.0.0.0:80", time.Millisecond); err == nil {
		t.Fatal("занятый порт принят молча")
	}
	if d.Addr() != "0.0.0.0:56000" {
		t.Fatalf("после отказа слушаем %q", d.Addr())
	}
	if _, gone := closed.Load("0.0.0.0:56000"); gone {
		t.Fatal("рабочий сокет закрыт из-за неудачной попытки переезда")
	}
}

func TestDataPlaneRelistenToTheSameAddressIsANoop(t *testing.T) {
	var closed sync.Map
	opens := 0
	d := newDataPlane()
	d.setOpen(func(addr string) (*listenGen, error) {
		opens++
		return fakeGen(addr, &closed), nil
	})
	d.setServe(func(*listenGen) {})
	if _, err := d.Start("0.0.0.0:56000"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := d.Relisten("0.0.0.0:56000", time.Millisecond); err != nil {
		t.Fatalf("relisten: %v", err)
	}
	if opens != 1 {
		t.Fatalf("сокет открыт %d раза на один и тот же адрес", opens)
	}
}

func TestNormalizeListenAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{":56000", "0.0.0.0:56000"},
		{" 127.0.0.1:41337 ", "127.0.0.1:41337"},
		{"0.0.0.0:0", "0.0.0.0:0"},
	} {
		got, err := normalizeListenAddr(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("normalizeListenAddr(%q) = %q, %v", tc.in, got, err)
		}
	}
	for _, bad := range []string{"", "56000", "0.0.0.0:70000", "0.0.0.0:http"} {
		if _, err := normalizeListenAddr(bad); err == nil {
			t.Fatalf("мусор %q принят как адрес", bad)
		}
	}
}

// Нулевой порт выбирает ядро, и наружу обязан уйти тот, что оно выдало
func TestOpenDataListenerReportsTheBoundPort(t *testing.T) {
	gen, err := openDataListener("127.0.0.1:0", &wrapPolicy{}, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer gen.close()
	_, port, err := net.SplitHostPort(gen.addr)
	if err != nil {
		t.Fatalf("адрес %q не разбирается: %v", gen.addr, err)
	}
	if port == "0" {
		t.Fatalf("отдали %q вместо порта, который выдало ядро", gen.addr)
	}
}

// Переезд не должен гасить релей: главный поток стоит на контексте, а не на
// первом сокете, иначе после дренажа процесс штатно выходит и его поднимает
// заново kubelet - каждые drain минут
func TestDrainedGenerationDoesNotEndTheProcess(t *testing.T) {
	var closed sync.Map
	alive := make(chan struct{})
	d := newDataPlane()
	d.setOpen(func(addr string) (*listenGen, error) { return fakeGen(addr, &closed), nil })
	// Акцептор поколения возвращается, как только сокет закрыт - ровно то, что
	// делает настоящий цикл на net.ErrClosed
	d.setServe(func(gen *listenGen) {
		for {
			if _, gone := closed.Load(gen.addr); gone {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	first, err := d.Start("0.0.0.0:56000")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	go func() {
		d.serve(first)
		close(alive)
	}()
	if _, err := d.Relisten("0.0.0.0:41337", 10*time.Millisecond); err != nil {
		t.Fatalf("relisten: %v", err)
	}
	select {
	case <-alive:
	case <-time.After(2 * time.Second):
		t.Fatal("акцептор первого поколения не завершился после дренажа")
	}
	// Приём при этом обязан продолжаться на новом адресе
	if d.Addr() != "0.0.0.0:41337" {
		t.Fatalf("после дренажа слушаем %q", d.Addr())
	}
}
