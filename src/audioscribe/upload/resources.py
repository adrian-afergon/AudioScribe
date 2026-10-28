import threading


class UnsafeCapacityError(RuntimeError):
    pass


def remaining_commitment(total: int | None, written: int, maximum: int) -> int:
    return max((maximum if total is None else total) - written, 0)


def can_admit(free_bytes: int, active_commitments: list[int], new_commitment: int,
              reserve_bytes: int, allocation_guard: int = 0) -> bool:
    return free_bytes - sum(active_commitments) - new_commitment >= reserve_bytes + allocation_guard


class DiskReservations:
    def __init__(self, reserve_bytes: int, allocation_guard: int = 0):
        self.reserve_bytes = reserve_bytes
        self.allocation_guard = allocation_guard
        self._commitments: dict[str, int] = {}
        self._guard = threading.Lock()
        self._frozen = False

    def admit(self, upload_id: str, commitment: int, free_bytes: int) -> bool:
        with self._guard:
            if self._frozen or upload_id in self._commitments or not can_admit(
                free_bytes, list(self._commitments.values()), commitment,
                self.reserve_bytes, self.allocation_guard,
            ):
                return False
            self._commitments[upload_id] = commitment
            return True

    def write(self, upload_id: str, write_chunk, sample_free_space) -> int:
        with self._guard:
            if self._frozen:
                raise UnsafeCapacityError("reserve protection is frozen")
            old_commitment = self._commitments[upload_id]
            try:
                written = write_chunk()
            except Exception:
                self._frozen = True
                raise
            if type(written) is not int or written < 0:
                self._frozen = True
                raise ValueError("write must return a nonnegative byte count")
            try:
                free_bytes = sample_free_space()
            except Exception:
                self._frozen = True
                raise
            if type(free_bytes) is not int or free_bytes < 0:
                self._frozen = True
                raise ValueError("free-space sample must be a nonnegative integer")
            if written > old_commitment:
                self._frozen = True
                raise ValueError("write exceeded its reserved commitment")
            new_commitment = max(old_commitment - written, 0)
            other_commitments = [value for key, value in self._commitments.items() if key != upload_id]
            if not can_admit(free_bytes, other_commitments, new_commitment,
                             self.reserve_bytes, self.allocation_guard):
                self._frozen = True
                raise UnsafeCapacityError("free space would breach the protected reserve")
            self._commitments[upload_id] = new_commitment
            return free_bytes

    def commitment(self, upload_id: str) -> int:
        with self._guard:
            return self._commitments[upload_id]

    def release(self, upload_id: str, blocking: bool = True) -> bool:
        """Locked release: a cancel racing a writer must not corrupt the
        commitment dict the writer iterates under the same guard.

        Non-blocking release returns False when a writer holds the guard; the
        writer's own exit path then completes the release (A6: cancellation
        flags first and never waits for the resource guard)."""
        if blocking:
            with self._guard:
                return self._commitments.pop(upload_id, None) is not None
        if not self._guard.acquire(blocking=False):
            return False
        try:
            return self._commitments.pop(upload_id, None) is not None
        finally:
            self._guard.release()

    def reserve_intact(self, free_bytes: int) -> bool:
        """True when current free space still covers every active commitment
        plus the protected reserve (A6 coherent monitor sample)."""
        with self._guard:
            return can_admit(free_bytes, list(self._commitments.values()), 0,
                             self.reserve_bytes, self.allocation_guard)

    @property
    def active(self) -> int:
        with self._guard:
            return len(self._commitments)
