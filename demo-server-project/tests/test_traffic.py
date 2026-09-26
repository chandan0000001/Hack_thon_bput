"""Traffic generator tests (T2): rate/duration honored, mix distribution,
graceful stop. All offline: fake sleeper/clock + recording shipper."""

import threading

from demo_server.scenarios import ScenarioBook
from demo_server.traffic import generate


class RecordingShipper:
    def __init__(self, fail_every: int = 0):
        self.calls: list[tuple[str, dict]] = []
        self.fail_every = fail_every

    def ship(self, action, payload):
        self.calls.append((action, payload))
        n = len(self.calls)
        ok = not (self.fail_every and n % self.fail_every == 0)

        class R:
            pass

        r = R()
        r.ok = ok
        r.attempts = 1
        r.action = action
        return r


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s
        self.delays.append(s)

    delays: list = []


def make_book():
    return ScenarioBook(rng=__import__("random").Random(42))


def test_generate_rate_and_duration_honored():
    shipper = RecordingShipper()
    clock = FakeClock()
    summary = generate(
        shipper, make_book(), {"net": 100},
        rate_per_min=600, duration_min=0.1, jitter=0.2,
        sleeper=clock.sleep, now_fn=clock.now,
    )
    assert summary.events_shipped == 60  # 600/min * 0.1 min
    assert len(shipper.calls) == 60
    # base interval 0.1s, jittered within +-20%
    assert len(clock.delays) == 59
    assert all(0.08 <= d <= 0.12 for d in clock.delays)
    assert abs(summary.elapsed_s - sum(clock.delays)) < 1e-9
    assert not summary.stopped_early
    assert summary.succeeded == 60 and summary.failed == 0


def test_generate_mix_distribution():
    shipper = RecordingShipper()
    clock = FakeClock()
    summary = generate(
        shipper, make_book(), {"net": 50, "benign": 50},
        rate_per_min=6000, duration_min=0.05, jitter=0.0,  # 300 ships
        sleeper=clock.sleep, now_fn=clock.now,
    )
    assert summary.events_shipped == 300
    net = summary.by_category["net_critical"]
    benign = summary.by_category["net_benign"] + summary.by_category["ato_benign"]
    # seeded rng: roughly half/half, tolerant band
    assert 100 <= net <= 200, net
    assert net + benign == 300
    assert set(summary.by_action) == {"analyze_network", "analyze_ato"}
    assert summary.success_rate == 1.0


def test_generate_graceful_stop_completes_current_send():
    shipper = RecordingShipper()
    clock = FakeClock()
    stop_event = threading.Event()

    def stop_after_5(template, result):
        if len(shipper.calls) >= 5:
            stop_event.set()

    summary = generate(
        shipper, make_book(), {"ato": 100},
        rate_per_min=60, duration_min=10, jitter=0.0,
        stop_event=stop_event, sleeper=clock.sleep, now_fn=clock.now,
        on_ship=stop_after_5,
    )
    assert summary.events_shipped == 5
    assert summary.stopped_early
    assert summary.succeeded == 5


def test_generate_validates_inputs():
    shipper = RecordingShipper()
    book = make_book()
    import pytest

    with pytest.raises(ValueError, match="rate_per_min"):
        generate(shipper, book, {"net": 100}, rate_per_min=0)
    with pytest.raises(ValueError, match="duration_min"):
        generate(shipper, book, {"net": 100}, rate_per_min=60, duration_min=-1)
    with pytest.raises(ValueError, match="jitter"):
        generate(shipper, book, {"net": 100}, rate_per_min=60, duration_min=1, jitter=1.0)
    with pytest.raises(ValueError, match="mix"):
        generate(shipper, book, {}, rate_per_min=60, duration_min=1)
