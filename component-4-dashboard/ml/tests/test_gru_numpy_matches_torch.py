"""A GRU written in plain NumPy gives the same outputs as torch.nn.GRU.

This shows the forecasting model is not a black box: the recurrent layer is
exactly the four equations below, applied once per week of the input window.
PyTorch's formulation (which differs from some textbooks) applies the reset
gate AFTER the hidden-state matrix multiply, inside the candidate state:

    r  = sigmoid(W_ir x + b_ir + W_hr h + b_hr)        reset gate
    z  = sigmoid(W_iz x + b_iz + W_hz h + b_hz)        update gate
    n  = tanh(W_in x + b_in + r * (W_hn h + b_hn))     candidate state
    h' = (1 - z) * n + z * h                           new hidden state

PyTorch stores the three gates stacked in the order (r, z, n) in
weight_ih_l0 (3H x I), weight_hh_l0 (3H x H) and the two bias vectors.
"""

import numpy as np
import torch


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def gru_numpy(x, W_ih, W_hh, b_ih, b_hh, h0=None):
    """x: (batch, time, inputs). Returns all hidden states (batch, time, H)."""
    H = W_hh.shape[1]
    W_ir, W_iz, W_in = np.split(W_ih, 3)
    W_hr, W_hz, W_hn = np.split(W_hh, 3)
    b_ir, b_iz, b_in = np.split(b_ih, 3)
    b_hr, b_hz, b_hn = np.split(b_hh, 3)

    h = np.zeros((x.shape[0], H)) if h0 is None else h0
    outputs = []
    for t in range(x.shape[1]):
        xt = x[:, t]
        r = sigmoid(xt @ W_ir.T + b_ir + h @ W_hr.T + b_hr)
        z = sigmoid(xt @ W_iz.T + b_iz + h @ W_hz.T + b_hz)
        n = np.tanh(xt @ W_in.T + b_in + r * (h @ W_hn.T + b_hn))
        h = (1 - z) * n + z * h
        outputs.append(h)
    return np.stack(outputs, axis=1)


def test_numpy_gru_matches_torch():
    torch.manual_seed(0)
    gru = torch.nn.GRU(input_size=7, hidden_size=32, num_layers=1, batch_first=True).double()
    x = torch.randn(5, 4, 7, dtype=torch.float64)   # 5 windows, 4 weeks, 7 inputs

    with torch.no_grad():
        expected, h_last = gru(x)

    weights = {name: p.detach().numpy() for name, p in gru.named_parameters()}
    got = gru_numpy(x.numpy(), weights["weight_ih_l0"], weights["weight_hh_l0"],
                    weights["bias_ih_l0"], weights["bias_hh_l0"])

    np.testing.assert_allclose(got, expected.numpy(), atol=1e-10)
    np.testing.assert_allclose(got[:, -1], h_last[0].numpy(), atol=1e-10)
