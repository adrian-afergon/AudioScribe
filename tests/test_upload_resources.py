import pytest

from audioscribe.upload.resources import DiskReservations, can_admit, remaining_commitment


def test_unknown_length_reserves_maximum():
    assert remaining_commitment(total=None, written=0, maximum=20_000_000_000) == 20_000_000_000


def test_known_length_commitment_decreases_by_written_bytes():
    assert remaining_commitment(total=100, written=35, maximum=500) == 65


def test_commitment_never_becomes_negative_after_overrun():
    assert remaining_commitment(total=100, written=101, maximum=500) == 0


def test_joint_commitments_no_double_count():
    assert can_admit(free_bytes=1000, active_commitments=[200, 300], new_commitment=250,
                     reserve_bytes=200, allocation_guard=50)
    assert not can_admit(free_bytes=1000, active_commitments=[200, 300], new_commitment=251,
                         reserve_bytes=200, allocation_guard=50)


def test_write_sample_precedes_reservation_release():
    reservations = DiskReservations(reserve_bytes=100)
    assert reservations.admit("one", 200, free_bytes=500)
    events = []

    reservations.write("one", lambda: events.append(("write", reservations._commitments["one"])) or 50,
                       lambda: events.append(("sample", reservations._commitments["one"])) or 450)

    assert events == [("write", 200), ("sample", 200)]
    assert reservations.commitment("one") == 150


def test_admissions_share_the_same_free_space_commitments():
    reservations = DiskReservations(reserve_bytes=100)

    assert reservations.admit("one", 250, free_bytes=500)
    assert not reservations.admit("two", 250, free_bytes=500)


def test_failed_post_write_sample_keeps_old_commitment():
    reservations = DiskReservations(reserve_bytes=100)
    assert reservations.admit("one", 200, free_bytes=500)

    try:
        reservations.write("one", lambda: 50, lambda: (_ for _ in ()).throw(OSError("sample failed")))
    except OSError as error:
        assert str(error) == "sample failed"
    else:
        raise AssertionError("sampling failure must propagate")

    assert reservations.commitment("one") == 200
    assert not reservations.admit("two", 10, free_bytes=500)


def test_external_consumption_freezes_reservations_before_release():
    reservations = DiskReservations(reserve_bytes=100)
    assert reservations.admit("one", 200, free_bytes=500)

    with pytest.raises(RuntimeError, match="reserve"):
        reservations.write("one", lambda: 50, lambda: 200)

    assert reservations.commitment("one") == 200
    assert not reservations.admit("two", 10, free_bytes=500)


def test_write_cannot_release_more_than_its_commitment():
    reservations = DiskReservations(reserve_bytes=100)
    assert reservations.admit("one", 200, free_bytes=500)

    with pytest.raises(ValueError, match="commitment"):
        reservations.write("one", lambda: 201, lambda: 500)

    assert reservations.commitment("one") == 200
    assert not reservations.admit("two", 10, free_bytes=500)


def test_decimal_gb_allocation_and_external_consumption():
    reservations = DiskReservations(reserve_bytes=25_000_000_000)
    assert reservations.admit("one", 20_000_000_000, free_bytes=50_000_000_000)
    assert not reservations.admit("two", 5_000_000_001, free_bytes=50_000_000_000)
    assert reservations.admit("two", 5_000_000_000, free_bytes=50_000_000_000)

    with pytest.raises(RuntimeError, match="reserve"):
        reservations.write(
            "one", lambda: 2_000_000_000, lambda: 30_000_000_000)

    assert reservations.commitment("one") == 20_000_000_000
    assert reservations.commitment("two") == 5_000_000_000
    assert not reservations.admit("three", 1, free_bytes=50_000_000_000)


def test_decimal_gb_short_write_releases_commitment_when_space_suffices():
    reservations = DiskReservations(reserve_bytes=25_000_000_000)
    assert reservations.admit("one", 20_000_000_000, free_bytes=50_000_000_000)
    assert reservations.admit("two", 5_000_000_000, free_bytes=50_000_000_000)

    free = reservations.write("one", lambda: 2_000_000_000, lambda: 49_000_000_000)
    assert free == 49_000_000_000
    assert reservations.commitment("one") == 18_000_000_000
    assert not reservations.admit("three", 5_000_000_000, free_bytes=49_000_000_000)
