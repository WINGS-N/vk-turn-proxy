package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
)

// defaultRelistenDrain - сколько старый сокет доживает после переезда.
//
// Клиенты держат прежний адрес в своём профиле и узнают новый только со
// следующей подпиской, так что рубить их в момент переезда значит наказать за
// нашу же перестановку
const defaultRelistenDrain = 5 * time.Minute

// listenGen - одно поколение слушающего сокета
type listenGen struct {
	addr     string
	listener net.Listener
	wrap     *wrap.Listener
	close    func()
}

// dataPlane держит слушающий сокет и умеет пересаживать его на другой адрес.
//
// Порядок здесь важнее удобства: сначала открываем новый сокет и только потом
// отпускаем старый. Занятый порт при таком порядке стоит ошибки в ответе, а не
// ноды, ушедшей в темноту
type dataPlane struct {
	mu    sync.Mutex
	gen   *listenGen
	open  func(addr string) (*listenGen, error)
	serve func(gen *listenGen)
	drain time.Duration
	done  <-chan struct{}
}

func newDataPlane() *dataPlane {
	return &dataPlane{drain: defaultRelistenDrain}
}

// dataPlaneSwitch собирается до того, как известны политика WRAP и параметры
// DTLS, поэтому обе функции доставляются позже
var dataPlaneSwitch = newDataPlane()

func (d *dataPlane) setOpen(open func(string) (*listenGen, error)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.open = open
}

func (d *dataPlane) setServe(serve func(*listenGen)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.serve = serve
}

// setDone задаёт сигнал остановки: по нему дренаж не ждёт свои минуты впустую
func (d *dataPlane) setDone(done <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.done = done
}

// Start открывает первый сокет. Обслуживает его вызывающий, а не мы: главный
// поток на этом и стоит
func (d *dataPlane) Start(addr string) (*listenGen, error) {
	normalized, err := normalizeListenAddr(addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	open := d.open
	d.mu.Unlock()
	if open == nil {
		return nil, errors.New("data plane has no listener factory")
	}
	gen, err := open(normalized)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.gen = gen
	d.mu.Unlock()
	return gen, nil
}

// Addr - адрес, на котором сейчас принимаем
func (d *dataPlane) Addr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen == nil {
		return ""
	}
	return d.gen.addr
}

// Relisten переносит приём на другой адрес и возвращает тот, что получился.
//
// Нулевой порт отдаёт выбор ядру, и тогда фактический адрес известен только
// после привязки - поэтому наружу уходит он, а не то, что просили
func (d *dataPlane) Relisten(addr string, drain time.Duration) (string, error) {
	normalized, err := normalizeListenAddr(addr)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen == nil || d.open == nil || d.serve == nil {
		return "", errors.New("data plane is not listening yet")
	}
	if normalized == d.gen.addr {
		return d.gen.addr, nil
	}
	gen, err := d.open(normalized)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", normalized, err)
	}
	old := d.gen
	d.gen = gen
	go d.serve(gen)
	if drain <= 0 {
		drain = d.drain
	}
	go d.retire(old, drain)
	log.Printf("data plane moved to %s, %s serves its sessions for another %s", gen.addr, old.addr, drain)
	return gen.addr, nil
}

// retire закрывает прежний сокет, дав его сессиям доработать
func (d *dataPlane) retire(gen *listenGen, drain time.Duration) {
	timer := time.NewTimer(drain)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-d.done:
	}
	log.Printf("data plane: closing the drained socket on %s", gen.addr)
	gen.close()
}

// normalizeListenAddr приводит адрес к виду host:port и отбивает мусор до того,
// как он доедет до сокета
func normalizeListenAddr(addr string) (string, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "", errors.New("empty listen address")
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", addr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return "", fmt.Errorf("listen address %q: port out of range", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(number)), nil
}
