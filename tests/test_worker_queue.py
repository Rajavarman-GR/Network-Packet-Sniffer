import queue
import threading
import time
import unittest

from core.worker_queue import put_until_stopped


class WorkerQueueTests(unittest.TestCase):
    def test_bounded_queue_applies_backpressure_then_delivers(self):
        target = queue.Queue(maxsize=1)
        target.put("occupies-slot")
        stop_event = threading.Event()
        result = []
        worker = threading.Thread(target=lambda: result.append(
            put_until_stopped(target, "next", stop_event, timeout=0.01)))
        worker.start()
        time.sleep(0.03)
        self.assertTrue(worker.is_alive())
        self.assertEqual("occupies-slot", target.get(timeout=1))
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual([True], result)
        self.assertEqual("next", target.get_nowait())

    def test_full_queue_producer_exits_when_shutdown_is_signaled(self):
        target = queue.Queue(maxsize=1)
        target.put("occupies-slot")
        stop_event = threading.Event()
        result = []
        worker = threading.Thread(target=lambda: result.append(
            put_until_stopped(target, "discarded", stop_event, timeout=0.01)))
        worker.start()
        time.sleep(0.03)
        stop_event.set()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual([False], result)


if __name__ == "__main__":
    unittest.main()
