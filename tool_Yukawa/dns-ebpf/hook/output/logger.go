package output

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

// HookLogger 是一个高性能日志记录器，专为大量Hook事件设计
type HookLogger struct {
	mu        sync.Mutex
	file      *os.File
	writer    *bufio.Writer
	flushTime time.Duration
	stopChan  chan struct{}
}

// NewHookLogger 创建一个新的HookLogger实例
// filePath: 日志文件路径
// bufferSize: 写入缓冲区大小（字节）
// flushInterval: 自动刷新间隔时间
func NewHookLogger(filePath string, bufferSize int, flushInterval time.Duration) (*HookLogger, error) {
	// 以追加模式打开或创建文件
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", filePath, err)
	}

	// 创建缓冲写入器
	writer := bufio.NewWriterSize(file, bufferSize)

	logger := &HookLogger{
		file:      file,
		writer:    writer,
		flushTime: flushInterval,
		stopChan:  make(chan struct{}),
	}

	// 启动定期刷新goroutine
	go logger.flushRoutine()

	return logger, nil
}

// LogHookEvent 记录一个Hook事件到日志文件
func (l *HookLogger) Log(info string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, err := fmt.Fprint(l.writer, info)

	// 如果缓冲区接近满，立即刷新
	if l.writer.Available() < 1024*1024 { // 当剩余空间小于1MB时刷新
		l.writer.Flush()
	}

	return err
}

// flushRoutine 定期刷新缓冲区到磁盘
func (l *HookLogger) flushRoutine() {
	ticker := time.NewTicker(l.flushTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.Flush()
		case <-l.stopChan:
			return
		}
	}
}

// Flush 将缓冲区中的数据刷新到磁盘
func (l *HookLogger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer.Flush()
}

// Close 关闭日志记录器并释放资源
func (l *HookLogger) Close() error {
	// 停止刷新goroutine
	close(l.stopChan)

	// 刷新并关闭文件
	l.Flush()
	return l.file.Close()
}
