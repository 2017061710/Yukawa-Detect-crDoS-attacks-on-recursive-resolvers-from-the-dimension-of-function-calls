package output

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// RedisWriter 以 RESP 协议直接写入 Redis，避免依赖重量级客户端。
type RedisWriter struct {
	cfg    RedisOutputOptions
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
}

// normalizeRedisConfig 补齐 Redis 连接所需的默认参数。
func normalizeRedisConfig(cfg RedisOutputOptions) RedisOutputOptions {
	if cfg.Address == "" {
		cfg.Address = "localhost:6379"
	}
	if cfg.ListKey == "" {
		cfg.ListKey = "dns_events"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 2 * time.Second
	}
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = 2 * time.Second
	}
	return cfg
}

// NewRedisWriter 创建 RedisWriter 并尝试建立连接（包含鉴权和选择 DB）。
func NewRedisWriter(cfg RedisOutputOptions) (*RedisWriter, error) {
	rw := &RedisWriter{cfg: normalizeRedisConfig(cfg)}
	if err := rw.ensureConn(); err != nil {
		return nil, err
	}
	return rw, nil
}

// ensureConn 对外暴露的连接检查入口，会持锁后调用 ensureConnLocked。
func (w *RedisWriter) ensureConn() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ensureConnLocked()
}

// ensureConnLocked 假定调用方已加锁，真正执行建连、鉴权与 ping。
func (w *RedisWriter) ensureConnLocked() error {
	if w.conn != nil {
		return nil
	}

	conn, err := net.DialTimeout("tcp", w.cfg.Address, w.cfg.ConnectTimeout)
	if err != nil {
		return fmt.Errorf("dial redis %s: %w", w.cfg.Address, err)
	}
	w.conn = conn
	w.reader = bufio.NewReader(conn)

	if w.cfg.Password != "" {
		if _, err := w.execLocked("AUTH", w.cfg.Password); err != nil {
			w.closeLocked()
			return fmt.Errorf("redis auth failed: %w", err)
		}
	}

	if w.cfg.DB > 0 {
		if _, err := w.execLocked("SELECT", strconv.Itoa(w.cfg.DB)); err != nil {
			w.closeLocked()
			return fmt.Errorf("redis select db %d: %w", w.cfg.DB, err)
		}
	}

	if _, err := w.execLocked("PING"); err != nil {
		w.closeLocked()
		return fmt.Errorf("redis ping failed: %w", err)
	}
	return nil
}

// execLocked 构造 RESP 帧并读取 redis 响应，仅支持 + / - / : 回复。
func (w *RedisWriter) execLocked(args ...string) (string, error) {
	if w.conn == nil {
		return "", errors.New("redis connection not initialized")
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(arg), arg)
	}

	if w.cfg.IOTimeout > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.cfg.IOTimeout))
	}
	if _, err := w.conn.Write(buf.Bytes()); err != nil {
		return "", err
	}

	if w.cfg.IOTimeout > 0 {
		_ = w.conn.SetReadDeadline(time.Now().Add(w.cfg.IOTimeout))
	}
	line, err := w.reader.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) == 0 {
		return "", errors.New("empty redis response")
	}

	switch line[0] {
	case '-':
		return "", errors.New(string(line[1:]))
	case '+', ':':
		return string(line[1:]), nil
	default:
		return "", fmt.Errorf("unsupported redis reply: %s", string(line))
	}
}

// PushJSON 将事件 payload 以 RPUSH 写入 Redis 列表，必要时自动重连一次。
func (w *RedisWriter) PushJSON(payload []byte) error {
	jsonValue := string(payload)

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureConnLocked(); err != nil {
		return err
	}

	if _, err := w.execLocked("RPUSH", w.cfg.ListKey, jsonValue); err != nil {
		w.closeLocked()
		if err2 := w.ensureConnLocked(); err2 != nil {
			return err
		}
		if _, err3 := w.execLocked("RPUSH", w.cfg.ListKey, jsonValue); err3 != nil {
			return err3
		}
	}
	return nil
}

// Close 对外暴露的关闭接口，保证并发安全。
func (w *RedisWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

// closeLocked 负责真正关闭连接及缓冲 Reader。
func (w *RedisWriter) closeLocked() error {
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	w.reader = nil
	return err
}
