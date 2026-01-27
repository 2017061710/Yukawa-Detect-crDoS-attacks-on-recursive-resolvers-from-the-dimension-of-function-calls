import time
import heapq
import threading
from dataclasses import dataclass
from typing import Dict, Generic, Hashable, Iterator, Optional, Tuple, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class _Entry(Generic[T]):
    expire_at_ns: int
    seq: int
    key: Hashable


class DelayQueue(Generic[T]):
    """
    多生产者 / 单消费者 的高性能延迟队列（按 CLOCK_BOOTTIME 的 ns 绝对时间过期）。

    put(value, expire_at_ns, update=True/False)
      - 若 key 不存在：插入
      - 若 key 已存在：
          update=True  -> 更新过期时间（和 value）
          update=False -> 不更新，直接返回 False

    迭代：
      for item in q:
          # item 一定是已经过期的
          ...

    close():
      - 让阻塞的消费者退出（StopIteration）
    """

    def __init__(self, timeout_ns: int = 5_000_000_000, clock: int = time.CLOCK_BOOTTIME):
        self._timeout_ns = int(timeout_ns)
        self._clock = clock

        self._cv = threading.Condition()
        self._heap: list[Tuple[int, int, Hashable]] = []  # (expire_at_ns, seq, key)
        self._items: Dict[Hashable, Tuple[int, T]] = {}   # key -> (expire_at_ns, value)

        self._seq = 0
        self._closed = False

    def now_ns(self) -> int:
        return time.clock_gettime_ns(self._clock)

    def close(self) -> None:
        """让消费者停止阻塞并结束迭代。"""
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def put(self, value: T, expire_at_ns: int, *, update: bool = True, key: Optional[Hashable] = None) -> bool:
        """
        插入/更新。
        - key 默认用 value（因此 value 需可 hash）；不方便时请显式传 key（比如任务 id）。
        - expire_at_ns 必须是 CLOCK_BOOTTIME 基准下的“绝对时间(ns)”
        返回：
          True  -> 成功插入或成功更新
          False -> 已存在且 update=False
        """
        if key is None:
            key = value  # 需要 value 是 hashable

        expire_at_ns = int(expire_at_ns)

        with self._cv:
            if self._closed:
                raise RuntimeError("DelayQueue is closed")

            old = self._items.get(key)
            if old is not None and not update:
                return False

            # 更新 dict 中的“当前真值”
            self._items[key] = (expire_at_ns, value)

            # 往堆里追加一条记录（旧记录会在消费时被丢弃）
            self._seq += 1
            heapq.heappush(self._heap, (expire_at_ns, self._seq, key))

            # 如果新插入/更新使“最早到期时间”变早，唤醒消费者
            # 简化策略：直接 notify（MPSC 下开销很小，也避免复杂比较）
            self._cv.notify()

            # 防止堆里陈旧条目无限增长：偶尔压缩一次
            self._maybe_compact_locked()

            return True

    def _maybe_compact_locked(self) -> None:
        # 经验阈值：堆大小远大于真实 items 时重建堆（O(n)，但触发不频繁）
        if len(self._heap) > (2 * len(self._items) + 1024):
            new_heap = []
            seq = self._seq
            for k, (exp, _) in self._items.items():
                seq += 1
                new_heap.append((exp, seq, k))
            heapq.heapify(new_heap)
            self._heap = new_heap
            self._seq = seq

    def __iter__(self) -> Iterator[T]:
        return self._expired_iter()

    def _expired_iter(self) -> Iterator[T]:
        """
        不断产出已过期的元素；若没有已过期元素则阻塞。
        close() 后停止迭代。
        """
        while True:
            with self._cv:
                while True:
                    if self._closed:
                        return

                    # 清理堆顶陈旧条目
                    while self._heap:
                        exp, seq, key = self._heap[0]
                        cur = self._items.get(key)
                        if cur is None:
                            heapq.heappop(self._heap)
                            continue
                        cur_exp, _ = cur
                        if cur_exp != exp:
                            heapq.heappop(self._heap)
                            continue
                        break  # 堆顶是有效条目

                    if not self._heap:
                        # 队列空：阻塞一段时间（timeout_ns），以便能响应 close()
                        self._cv.wait(timeout=self._timeout_ns / 1e9)
                        continue

                    exp, seq, key = self._heap[0]
                    now = self.now_ns()

                    if exp <= now:
                        # 到期：弹出并从 dict 移除（确保只消费一次）
                        heapq.heappop(self._heap)
                        cur_exp, value = self._items.pop(key)  # cur_exp == exp
                        item = value
                        break

                    # 未到期：等待到期或被新 put() 唤醒；也不超过 timeout_ns
                    wait_ns = exp - now
                    if self._timeout_ns > 0:
                        wait_ns = min(wait_ns, self._timeout_ns)
                    self._cv.wait(timeout=wait_ns / 1e9)

            # 把处理放到锁外，避免阻塞生产者
            yield item


# import threading
# import time

# q = DelayQueue()

# def producer(name: str):
#     for i in range(5):
#         k = f"{name}-{i}"
#         expire = q.now_ns() + 1_000_000_000  # 1s 后到期
#         q.put(k, expire, update=True, key=k)
#         time.sleep(0.2)

# def consumer():
#     for item in q:
#         print("expired:", item)

# t1 = threading.Thread(target=producer, args=("p1",), daemon=True)
# t2 = threading.Thread(target=producer, args=("p2",), daemon=True)
# tc = threading.Thread(target=consumer, daemon=True)

# t1.start(); t2.start(); tc.start()

# time.sleep(4)
# q.close()
# tc.join(timeout=1)
