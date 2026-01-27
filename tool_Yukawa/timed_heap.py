import heapq
from dataclasses import dataclass, field
from typing import Any, List, Tuple

@dataclass
class TimestampedItem:
    """
    用于堆中的数据项，包含时间戳和对象。
    dataclass 和 __lt__ 方法确保了堆可以根据时间戳正确排序。
    """
    timestamp: int
    obj: Any
    # _index 是一个技巧，用于在时间戳相同时，避免比较 obj（以防 obj 不可比较），
    # 保证堆操作的稳定性。它按插入顺序递增。
    _index: int = field(default=0, init=False)

    def __lt__(self, other):
        # 首先比较时间戳，如果时间戳相同，则比较内部索引
        if self.timestamp == other.timestamp:
            return self._index < other._index
        return self.timestamp < other.timestamp


class TimedHeap:
    """
    一个基于堆的时间戳队列。

    该类允许添加带有时间戳的对象，并能获取所有时间戳小于给定值的对象。
    """

    def __init__(self):
        """初始化一个空的堆。"""
        self._heap = []
        self._counter = 0  # 用于 _index，以保证唯一性和插入顺序

    def add(self, obj: Any, timestamp: int):
        """
        添加一个对象及其关联的时间戳到堆中。

        Args:
            obj (Any): 要添加的对象。
            timestamp (int): 关联的时间戳。
        """
        item = TimestampedItem(timestamp=timestamp, obj=obj)
        item._index = self._counter
        self._counter += 1
        heapq.heappush(self._heap, item)

    def get_older_than(self, threshold_timestamp: int) -> List[Any]:
        """
        获取并移除所有时间戳严格小于阈值的所有对象。

        Args:
            threshold_timestamp (int): 时间戳阈值。

        Returns:
            List[Any]: 包含所有符合条件的对象的列表。如果没有对象符合条件，则返回空列表。
        """
        results = []
        
        # 持续检查堆顶元素，直到堆为空或堆顶元素的时间戳不再小于阈值
        while self._heap and self._heap[0].timestamp < threshold_timestamp:
            # 弹出时间戳最小的元素
            item = heapq.heappop(self._heap)
            # 将其对象部分添加到结果列表中
            results.append(item.obj)
            
        return results

# --- 使用示例 ---
if __name__ == "__main__":
    # 创建一个 TimedHeap 实例
    my_heap = TimedHeap()

    # 添加一些带时间戳的对象
    my_heap.add("event_a", 300)
    my_heap.add("event_b", 100)
    my_heap.add("event_c", 400)
    my_heap.add("event_d", 200)
    # 添加一个重复时间戳的测试
    my_heap.add("event_b_prime", 100)

    print("--- 初始堆状态后 ---")
    # 此时堆内大致为 [b(100), d(200), c(400), a(300)], 但 b_prime(100) 在 b(100) 之后
    # 直接打印堆内容可以看到内部结构
    temp_list = sorted(list(my_heap._heap), key=lambda x: (x.timestamp, x._index))
    print(f"当前堆中所有项 (按时间戳排序): {[(item.timestamp, item.obj) for item in temp_list]}")

    # 获取时间戳小于 250 的所有对象
    print("\n--- 获取时间戳 < 250 的对象 ---")
    older_events = my_heap.get_older_than(250)
    print(f"获取到的对象: {older_events}") # 应输出 ['event_b', 'event_b_prime', 'event_d']

    print("\n--- 操作后剩余堆状态 ---")
    # event_a(300) 和 event_c(400) 仍然在堆里
    temp_list_remaining = sorted(list(my_heap._heap), key=lambda x: (x.timestamp, x._index))
    print(f"剩余堆中所有项 (按时间戳排序): {[(item.timestamp, item.obj) for item in temp_list_remaining]}")

    # 再次尝试获取，但阈值较低，应该返回空列表
    print("\n--- 获取时间戳 < 250 的对象 (再次调用) ---")
    older_events_again = my_heap.get_older_than(250)
    print(f"获取到的对象: {older_events_again}") # 应输出 []

    # 获取剩下的所有对象
    print("\n--- 获取时间戳 < 500 的对象 (获取全部剩余) ---")
    all_remaining = my_heap.get_older_than(500)
    print(f"获取到的对象: {all_remaining}") # 应输出 ['event_a', 'event_c']

    print("\n--- 最终堆状态 ---")
    print(f"最终堆中所有项: {[(item.timestamp, item.obj) for item in my_heap._heap]}") # 应输出 []