# coding=utf-8

from collections import deque
import atexit
import itertools
import queue
import threading
import weakref
import os
import logging


# 任务对象接口
class Runnable(object):

    def run(self):
        raise NotImplemented()


# 同步锁对象，方便实现同步任务
class SyncObject(object):
    def __init__(self):
        # self.so_mutex = threading.Lock()
        self.so_mutex = threading.RLock()
        self.so_cond = threading.Condition(self.so_mutex)

    def __enter__(self):
        return self.so_mutex.__enter__()

    def __exit__(self, *args):
        return self.so_mutex.__exit__(*args)

    def wait(self, timeout=None):
        self.so_cond.wait(timeout)

    def notify(self):
        return self.so_cond.notify()

    def notifyAll(self):
        return self.so_cond.notify_all()


# 双端队列
class BlockingDeque(queue.Queue, SyncObject):
    def __init__(self):
        queue.Queue.__init__(self)
        SyncObject.__init__(self)
        self._add_lock = threading.Lock()
        self._add_first_flag = True

    # 向前端添加节点
    def addFirst(self, item):
        with self._add_lock:
            self._add_first_flag = True
            self.put(item)

    # 向后端添加节点
    def addLast(self, item):
        with self._add_lock:
            self._add_first_flag = False
            self.put(item)

    # Initialize the queue representation
    def _init(self, maxsize):
        self.queue = deque()

    def _qsize(self):
        return len(self.queue)

    # Put a new item in the queue
    def _put(self, item):
        if self._add_first_flag:
            self.queue.appendleft(item)
        else:
            self.queue.append(item)

    # Get an item from the queue
    def _get(self):
        return self.queue.popleft()


# 拒绝执行任务回调接口
class RejectedExecutionHandler(object):

    def rejectedExecution(self, r, executor):
        raise NotImplemented()


# 线程池实现
class MiniThreadPoolExecutor(object):
    # Used to assign unique thread names when thread_name_prefix is not supplied.
    _counter = itertools.count().__next__

    def __init__(self, blocking_deque, max_workers=None, thread_name_prefix=''):
        """Initializes a new ThreadPoolExecutor instance.
        Args:
            max_workers: The maximum number of threads that can be used to
                execute the given calls.
            thread_name_prefix: An optional name prefix to give our threads.
        """
        if max_workers is None:
            # Use this number because ThreadPoolExecutor is often
            # used to overlap I/O instead of CPU work.
            max_workers = (os.cpu_count() or 1) * 5
        if max_workers <= 0:
            raise ValueError("max_workers must be greater than 0")

        self._max_workers = max_workers
        self._work_queue = blocking_deque
        self._threads = set()
        self._shutdown = False
        self._shutdown_lock = threading.Lock()
        self._thread_name_prefix = (thread_name_prefix or
                                    ("MiniThreadPoolExecutor-%d" % self._counter()))
        self._rej_handler = None

    # 对线程池初始化
    def prestartAllThreads(self):
        # When the executor gets lost, the weakref callback will wake up
        # the worker threads.
        def weakref_cb(_, q=self._work_queue):
            q.addLast(None)

        if len(self._threads) == self._max_workers:
            return

        for num_threads in range(self._max_workers):
            thread_name = '%s_%d' % (self._thread_name_prefix or self,
                                     num_threads)
            t = threading.Thread(name=thread_name, target=_worker,
                                 args=(weakref.ref(self, weakref_cb),
                                       self._work_queue))
            t.daemon = True
            t.start()
            self._threads.add(t)
            _threads_queues[t] = self._work_queue

    # 添加拒绝执行任务接口对象
    def setRejectedExecutionHandler(self, handler):
        self._rej_handler = handler

    # 停止线程池
    def shutdown(self, wait=True):
        with self._shutdown_lock:
            self._shutdown = True
            for i in range(self._max_workers):
                self._work_queue.addLast(None)
            with self._work_queue:
                self._work_queue.notifyAll()
        if wait:
            for t in self._threads:
                t.join()


# 退出时销毁线程池中的线程
_threads_queues = weakref.WeakKeyDictionary()
_shutdown = False
def _python_exit():
    global _shutdown
    _shutdown = True
    items = list(_threads_queues.items())
    for t, q in items:
        q.addLast(None)
    for t, q in items:
        t.join()

atexit.register(_python_exit)

# 线程池内线程回调函数
def _worker(executor_reference, work_queue):
    try:
        while True:
            work_item = work_queue.get(block=True)
            is_stop = False
            executor = executor_reference()
            if _shutdown or executor is None or executor._shutdown:
                is_stop = True

            if work_item is not None:
                if is_stop:
                    if executor._rej_handler:
                        executor._rej_handler.rejectedExecution(work_item, executor)
                else:
                    work_item.run()
                # Delete references to object. See issue16284
                del work_item
                del executor
                continue

            del executor
            if is_stop:
                return
    except BaseException as e:
        logging.exception(e)
