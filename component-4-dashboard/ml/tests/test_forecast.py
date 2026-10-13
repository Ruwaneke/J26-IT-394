import numpy as np
import pandas as pd
import pytest
import torch

from src.forecast import (Standardiser, baseline_predictions, build_panel, make_windows, masked_huber,
                          predict, smape, split_origins, target_weeks, train_model)


def make_dw(rows):
    """rows: list of (developer_id, week, vuln_count, fix_rate, active)."""
    df = pd.DataFrame(rows, columns=["developer_id", "week", "vuln_count", "fix_rate", "active"])
    df["ignore_rate"] = df["fix_rate"].map(lambda f: np.nan if np.isnan(f) else 1 - f)
    df["avg_response_time"] = df["fix_rate"].map(lambda f: np.nan if np.isnan(f) else 300.0)
    df["repeat_count"] = df["vuln_count"] // 2
    df["severity_weighted_load"] = df["vuln_count"] * 2
    return df


def synthetic_dw(n_dev=6, n_weeks=16, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for d in range(n_dev):
        for w in range(1, n_weeks + 1):
            active = rng.random() > 0.1
            v = int(rng.poisson(4)) if active else 0
            f = float(rng.uniform(0.2, 0.9)) if v > 0 else np.nan
            rows.append((f"D{d}", w, v, f, active))
    return make_dw(rows)


@pytest.mark.parametrize("window", [3, 4])
def test_split_is_strictly_chronological(cfg, window):
    h = cfg["forecast"]["horizon"]
    train_o, val_o, test_o = split_origins(cfg, window, cfg["study"]["n_weeks"])
    panel = build_panel(synthetic_dw(), cfg, 9)
    weeks = {}
    for name, origins in [("train", train_o), ("val", val_o), ("test", test_o)]:
        w = make_windows(panel, window, h, origins)
        assert len(w.X) > 0
        weeks[name] = target_weeks(sorted(set(w.origin)), h)
    assert max(weeks["train"]) < min(weeks["val"])
    assert max(weeks["val"]) < min(weeks["test"])
    assert weeks["test"] == [13, 14, 15, 16]
    assert max(weeks["train"]) <= cfg["forecast"]["split"]["train_max_target_week"]


def test_carry_forward_and_target_mask(cfg):
    dw = make_dw([
        ("D", 1, 0, np.nan, False),   # inactive, before any known value
        ("D", 2, 4, 0.5, True),
        ("D", 3, 0, np.nan, False),   # inactive
        ("D", 4, 0, np.nan, True),    # active, zero detections
        ("D", 5, 2, 1.0, True),
        ("D", 6, 3, 0.0, True),
    ])
    panel = build_panel(dw, cfg, stats_max_week=6)
    fix_col = cfg["forecast"]["inputs"].index("fix_rate")
    fix_in = panel.inputs[0, :, fix_col]
    train_mean = np.nanmean([0.5, 1.0, 0.0])
    assert fix_in[0] == pytest.approx(train_mean)   # leading gap: train mean
    assert fix_in[2] == pytest.approx(0.5)          # carried forward
    assert fix_in[3] == pytest.approx(0.5)

    w = make_windows(panel, window=2, horizon=2, origins=[2])   # targets weeks 3 and 4
    # [vuln w3, vuln w4, fix w3, fix w4]: w3 inactive -> masked; w4 active with 0 detections
    assert w.M[0].tolist() == [0, 1, 0, 0]
    assert w.Y[0, 1] == 0


def test_standardiser_uses_train_weeks_only(cfg):
    panel = build_panel(synthetic_dw(), cfg, 9)
    before = Standardiser(panel, 9, 2)
    panel.inputs[:, 9:] *= 1000
    panel.target_vuln[:, 9:] += 1000
    after = Standardiser(panel, 9, 2)
    assert np.allclose(before.x_mean, after.x_mean) and np.allclose(before.x_sd, after.x_sd)
    assert np.allclose(before.y_mean, after.y_mean) and np.allclose(before.y_sd, after.y_sd)


def test_smape_handles_zeros():
    assert smape([0, 0], [0, 0]) == 0.0      # 0/0 counted as perfect
    assert smape([0], [2]) == pytest.approx(200.0)
    assert smape([1], [3]) == pytest.approx(100.0)


def test_masked_loss_ignores_masked_targets():
    target = torch.zeros(1, 4)
    mask = torch.tensor([[1.0, 1.0, 0.0, 0.0]])
    a = masked_huber(torch.tensor([[0.5, 0.5, 0.0, 0.0]]), target, mask, 1.0)
    b = masked_huber(torch.tensor([[0.5, 0.5, 99.0, -99.0]]), target, mask, 1.0)
    assert a.item() == pytest.approx(b.item())


def test_baselines(cfg):
    dw = make_dw([("D", w, w, 0.2 * w, True) for w in range(1, 5)] +
                 [("D", 5, 0, np.nan, True), ("D", 6, 0, np.nan, True)])
    panel = build_panel(dw, cfg, 6)
    w = make_windows(panel, window=4, horizon=2, origins=[4])
    b = baseline_predictions(panel, w, window=4, horizon=2)
    assert b["naive"][0] == pytest.approx([4, 4, 0.8, 0.8])
    assert b["mean4"][0] == pytest.approx([2.5, 2.5, 0.5, 0.5])
    assert b["linear"][0] == pytest.approx([5, 6, 1.0, 1.0])  # fix 1.0, 1.2 clipped to 1


@pytest.mark.parametrize("mode", ["raw", "residual"])
def test_training_is_seeded_and_clipped(cfg, mode):
    panel = build_panel(synthetic_dw(), cfg, 9)
    train_o, val_o, test_o = split_origins(cfg, 4, 16)
    tr, va, te = (make_windows(panel, 4, 2, o) for o in (train_o, val_o, test_o))
    std = Standardiser(panel, 9, 2, mode, tr)
    tcfg = dict(cfg["forecast"]["training"], max_epochs=3, patience=2)
    preds = [predict(train_model(tr, std, "gru", 8, 0.1, tcfg, seed=1, val_w=va)[0], te, std)
             for _ in range(2)]
    assert np.array_equal(preds[0], preds[1])
    assert preds[0].shape == (len(te.X), 4)
    assert (preds[0][:, :2] >= 0).all()
    assert ((preds[0][:, 2:] >= 0) & (preds[0][:, 2:] <= 1)).all()


def test_residual_mode_adds_the_4_week_mean(cfg):
    panel = build_panel(synthetic_dw(), cfg, 9)
    tr = make_windows(panel, 4, 2, split_origins(cfg, 4, 16)[0])
    std = Standardiser(panel, 9, 2, "residual", tr)
    zero_residual = (0 - std.y_mean) / std.y_sd          # network output meaning "residual = 0"
    P = std.prediction(np.tile(zero_residual, (len(tr.X), 1)), tr)
    assert np.allclose(P[:, :2], np.clip(tr.base[:, :2], 0, None))
    assert np.allclose(P[:, 2:], np.clip(tr.base[:, 2:], 0, 1))
    # training target is the standardised residual
    expected = (tr.Y - tr.base - std.y_mean) / std.y_sd
    assert np.allclose(std.target(tr)[tr.M == 1], expected[tr.M == 1])


def test_fixed_step_refit(cfg):
    panel = build_panel(synthetic_dw(), cfg, 16)
    w = make_windows(panel, 4, 2, range(4, 15))
    std = Standardiser(panel, 16, 2)
    tcfg = dict(cfg["forecast"]["training"], batch_size=16)
    _, epoch, _ = train_model(w, std, "gru", 8, 0.1, tcfg, seed=0, max_steps=10)
    steps_per_epoch = int(np.ceil(len(w.X) / 16))
    assert epoch == int(np.ceil(10 / steps_per_epoch))


def test_future_window_has_masked_targets(cfg):
    panel = build_panel(synthetic_dw(), cfg, 16)
    w = make_windows(panel, 4, 2, [16], require_targets=False)
    assert len(w.X) == 6 and w.M.sum() == 0
