"""Small bounded-queue helper for workers that must stop cleanly."""

import queue


def put_until_stopped(target_queue, item, stop_event, timeout=0.1):
    """Put with backpressure, returning False when shutdown is requested."""
    while not stop_event.is_set():
        try:
            target_queue.put(item, timeout=timeout)
            return True
        except queue.Full:
            continue
    return False
