#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import subprocess
import threading
import webbrowser
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

try:
    from solders.pubkey import Pubkey as SoldersPubkey
except ImportError:
    SoldersPubkey = None


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
ENV_PATH = REPO_ROOT / ".env"
TIP_ACCOUNTS_PATH = REPO_ROOT / "各家tip账户.txt"
PUBLIC_RPC_URL = "https://api.mainnet-beta.solana.com"
RPC_TIMEOUT_SECS = 45
MAX_WINDOW = 300
DEFAULT_PORT = 8765
DEFAULT_HOST = "127.0.0.1"
MULTIPLE_ACCOUNTS_BATCH_SIZE = 100
RAYDIUM_AMM_POOL_DATA_LEN = 752
METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
WRAPPED_SOL_MINT = "So11111111111111111111111111111111111111112"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}
PDA_MARKER = b"ProgramDerivedAddress"
ED25519_FIELD_PRIME = 2**255 - 19
ED25519_D = (-121665 * pow(121666, -1, ED25519_FIELD_PRIME)) % ED25519_FIELD_PRIME
ED25519_SQRT_M1 = pow(2, (ED25519_FIELD_PRIME - 1) // 4, ED25519_FIELD_PRIME)
TOKEN_2022_MINT_SIZE = 82
TOKEN_2022_PADDING_END = 165
TOKEN_2022_MINT_ACCOUNT_TYPE_OFFSET = 165
TOKEN_2022_TLV_START = 166
TOKEN_2022_MINT_ACCOUNT_TYPE = 1
TOKEN_2022_METADATA_POINTER_EXTENSION = 18
TOKEN_2022_TOKEN_METADATA_EXTENSION = 19
TOKEN_METADATA_INTERFACE_DISCRIMINATOR = bytes([112, 132, 90, 90, 11, 88, 157, 87])


AccountValidator = Callable[[bytes], bool]


@dataclass(frozen=True)
class DexProgramSpec:
    dex_name: str
    anchor_account_name: str | None = None
    layout_validator: AccountValidator | None = None
    mint_a_offset: int | None = None
    mint_b_offset: int | None = None


@dataclass(frozen=True)
class ResolvedInstruction:
    program_id: str
    accounts: list[str]


@dataclass(frozen=True)
class PoolInfo:
    dex_name: str
    pool_address: str
    mint_a: str
    mint_b: str
    symbol_a: str | None = None
    symbol_b: str | None = None


def is_raydium_amm_pool_account(data: bytes) -> bool:
    if len(data) != RAYDIUM_AMM_POOL_DATA_LEN:
        return False

    status = int.from_bytes(data[0:8], "little")
    open_orders = data[528:560]
    target_orders = data[560:592]
    serum_market = data[592:624]

    return (
        status != 0
        and any(open_orders)
        and any(target_orders)
        and any(serum_market)
    )


DEX_PROGRAMS: dict[str, DexProgramSpec] = {
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK": DexProgramSpec(
        dex_name="Raydium Concentrated Liquidity",
        anchor_account_name="PoolState",
        mint_a_offset=73,
        mint_b_offset=105,
    ),
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C": DexProgramSpec(
        dex_name="Raydium CPMM",
        anchor_account_name="PoolState",
        mint_a_offset=168,
        mint_b_offset=200,
    ),
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": DexProgramSpec(
        dex_name="Raydium Liquidity Pool V4",
        layout_validator=is_raydium_amm_pool_account,
        mint_a_offset=400,
        mint_b_offset=432,
    ),
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": DexProgramSpec(
        dex_name="Whirlpools Program",
        anchor_account_name="Whirlpool",
        mint_a_offset=101,
        mint_b_offset=181,
    ),
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo": DexProgramSpec(
        dex_name="Meteora DLMM Program",
        anchor_account_name="LbPair",
        mint_a_offset=88,
        mint_b_offset=120,
    ),
    "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB": DexProgramSpec(
        dex_name="Meteora Pools Program",
        anchor_account_name="Pool",
        mint_a_offset=40,
        mint_b_offset=72,
    ),
    "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG": DexProgramSpec(
        dex_name="Meteora DAMM v2",
        anchor_account_name="Pool",
        mint_a_offset=168,
        mint_b_offset=200,
    ),
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA": DexProgramSpec(
        dex_name="Pump.fun AMM",
        anchor_account_name="Pool",
        mint_a_offset=43,
        mint_b_offset=75,
    ),
}


HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>区块链数据高级查询</title>
  <style>
    :root {
      --bg-1: #f5f1e8;
      --bg-2: #dce9df;
      --card: rgba(255, 255, 255, 0.88);
      --line: rgba(45, 69, 58, 0.12);
      --text: #1d2c26;
      --muted: #567268;
      --accent: #0b7a5a;
      --accent-2: #0d5e78;
      --navy-1: #2e4a5f;
      --navy-2: #1a2d42;
      --navy-3: #152433;
      --danger: #b33a3a;
      --shadow: 0 22px 60px rgba(25, 52, 44, 0.15);
      --radius: 22px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "SimSun", "Songti SC", "STSong", serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(255, 255, 255, 0.92), transparent 32%),
        radial-gradient(circle at bottom right, rgba(20, 94, 120, 0.18), transparent 26%),
        linear-gradient(135deg, var(--bg-1), var(--bg-2));
      padding: 28px;
    }

    .shell {
      max-width: 1400px;
      margin: 0 auto;
      display: grid;
      gap: 18px;
    }

    .hero,
    .panel {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
    }

    .hero {
      padding: 16px 28px;
      display: grid;
      gap: 6px;
    }

    .hero-query {
      padding: 22px 26px;
    }

    .hero-title-row {
      display: flex;
      align-items: flex-start;
      gap: 16px;
    }

    .brand-mark {
      width: 44px;
      height: 44px;
      border-radius: 14px;
      flex-shrink: 0;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      box-shadow: 0 8px 22px rgba(11, 122, 90, 0.28);
      position: relative;
    }

    .brand-mark::after {
      content: "";
      position: absolute;
      inset: 10px;
      border-radius: 6px;
      border: 2px solid rgba(255, 255, 255, 0.85);
      opacity: 0.9;
    }

    .hero-title-row h1 {
      margin: 0;
      font-size: clamp(20px, 2.8vw, 28px);
      line-height: 1.1;
      font-weight: 800;
      letter-spacing: 0.02em;
    }

    .hero-lead {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.4;
      max-width: 720px;
    }

    .eyebrow {
      font-size: 13px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent-2);
      font-weight: 700;
    }

    h1 {
      margin: 0;
      font-size: clamp(28px, 4vw, 46px);
      line-height: 1.05;
    }

    .hero p {
      margin: 0;
      color: var(--muted);
      font-size: 15px;
      max-width: 840px;
    }

    .panel {
      padding: 22px;
    }

    form {
      display: grid;
      gap: 16px;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }

    .form-row {
      display: grid;
      gap: 16px;
      margin-bottom: 16px;
    }

    .form-row:last-child {
      margin-bottom: 0;
    }

    .form-row-cols {
      display: grid;
      grid-template-columns: minmax(180px, 220px) minmax(0, 1fr);
      gap: 16px;
      align-items: start;
    }

    .control-grid {
      display: grid;
      grid-template-columns: minmax(300px, 0.42fr) minmax(540px, 0.58fr);
      gap: 24px;
      align-items: start;
    }

    .control-col {
      display: grid;
      gap: 16px;
      align-content: start;
    }

    .field-block {
      display: grid;
      gap: 8px;
      min-width: 0;
    }

    .field-label-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
    }

    .field-label-row .lbl-en {
      font-weight: 600;
      color: var(--muted);
      font-size: 13px;
    }

    .info-tip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      font-size: 12px;
      font-weight: 800;
      color: var(--muted);
      border: 1px solid rgba(41, 68, 57, 0.18);
      background: rgba(255, 255, 255, 0.8);
      cursor: help;
      flex-shrink: 0;
    }

    .hash-input-row {
      display: flex;
      flex-wrap: wrap;
      align-items: stretch;
      gap: 12px;
    }

    .input-icon-wrap {
      flex: 1;
      min-width: 200px;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 4px 6px 4px 14px;
      border: 1px solid rgba(41, 68, 57, 0.18);
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.95);
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    .input-icon-wrap:focus-within {
      border-color: rgba(26, 45, 66, 0.45);
      box-shadow: 0 0 0 4px rgba(26, 45, 66, 0.08);
    }

    .input-icon-wrap .glyph-input {
      font-size: 18px;
      line-height: 1;
      opacity: 0.55;
      flex-shrink: 0;
      user-select: none;
    }

    .input-icon-wrap input {
      flex: 1;
      min-width: 0;
      border: 0;
      background: transparent;
      box-shadow: none;
      padding: 11px 12px 11px 0;
      border-radius: 0;
    }

    .input-icon-wrap input:focus {
      outline: none;
      transform: none;
      box-shadow: none;
    }

    .btn-identify {
      flex-shrink: 0;
      align-self: center;
      white-space: nowrap;
      border-radius: 14px;
      padding: 12px 20px;
      font-size: 14px;
    }

    
    
    .btn-link-clear {
      background: none !important;
      border: 0 !important;
      box-shadow: none !important;
      color: var(--muted);
      font-weight: 600;
      font-size: 14px;
      padding: 10px 8px;
      border-radius: 10px;
    }

    .btn-link-clear:hover {
      color: var(--text);
      background: rgba(41, 68, 57, 0.06) !important;
      transform: none;
    }

    .btn-submit-main {
      border-radius: 14px;
      padding: 14px 32px;
      font-size: 16px;
      font-weight: 800;
    }

    label {
      display: grid;
      gap: 8px;
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
    }

    label.field-label-row {
      display: flex;
      gap: 12px;
    }

    input,
    select {
      width: 100%;
      border: 1px solid rgba(41, 68, 57, 0.18);
      border-radius: 14px;
      padding: 13px 14px;
      font-size: 15px;
      color: var(--text);
      background: rgba(255, 255, 255, 0.9);
      transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
    }

    input:focus,
    select:focus {
      outline: none;
      border-color: rgba(11, 122, 90, 0.6);
      box-shadow: 0 0 0 4px rgba(11, 122, 90, 0.1);
      transform: translateY(-1px);
    }

    select:disabled {
      opacity: 0.72;
      cursor: not-allowed;
    }

    .field-stack {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .field-stack label {
      display: block;
      margin: 0;
      gap: 0;
      white-space: nowrap;
      flex-shrink: 0;
      min-width: 88px;
      text-align: left;
    }

    .field-stack input,
    .field-stack select {
      flex: 1;
      margin: 0;
      min-width: 0;
    }

    .field-note {
      font-size: 13px;
      color: var(--muted);
      font-weight: 500;
    }

    .actions {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .control-actions {
      padding-top: 2px;
    }

    button {
      border: 0;
      border-radius: 999px;
      padding: 12px 20px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.18s ease, opacity 0.18s ease, box-shadow 0.18s ease;
    }

    button:hover {
      transform: translateY(-1px);
    }

    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    .primary {
      color: #fff;
      background: linear-gradient(180deg, #2d5d5f 0%, #244750 52%, #1c3a40 100%);
      box-shadow: 0 12px 28px rgba(45, 93, 95, 0.28);
    }

    .secondary {
      background: rgba(255, 255, 255, 0.72);
      color: var(--text);
      border: 1px solid rgba(41, 68, 57, 0.12);
    }

    .compact {
      justify-self: start;
      padding: 10px 16px;
      font-size: 14px;
    }

    .status {
      min-height: 26px;
      font-size: 14px;
      color: var(--muted);
    }

    .status.error {
      color: var(--danger);
    }

    .status.warn {
      color: #8a6d2f;
      font-weight: 600;
    }

    .status.loading::before {
      content: "";
      display: inline-block;
      width: 12px;
      height: 12px;
      margin-right: 8px;
      border-radius: 50%;
      border: 2px solid rgba(11, 122, 90, 0.18);
      border-top-color: var(--accent);
      vertical-align: -2px;
      animation: spin 0.7s linear infinite;
    }

    .progress-wrap {
      height: 8px;
      border-radius: 999px;
      background: rgba(11, 122, 90, 0.12);
      overflow: hidden;
      margin-top: 8px;
      opacity: 0;
      transition: opacity 0.2s ease;
    }

    .progress-wrap.show {
      opacity: 1;
    }

    .progress-bar {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #0b7a5a, #0d5e78);
      transition: width 0.25s ease;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .summary {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }

    .metric {
      padding: 16px 14px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.66);
      border: 1px solid rgba(41, 68, 57, 0.1);
      min-height: 92px;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }

    .metric .label {
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 7px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .metric .value {
      font-size: 22px;
      font-weight: 800;
      line-height: 1.1;
      white-space: nowrap;
    }

    .metric .value.range-value {
      font-size: 16px;
      letter-spacing: 0.01em;
    }

    .hint {
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }

    .render-count {
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 13px;
    }

    .table-wrap {
      overflow: visible;
      border-radius: 18px;
      border: 1px solid rgba(41, 68, 57, 0.12);
      background: rgba(255, 255, 255, 0.6);
    }

    .table-scroll {
      overflow: visible;
    }

    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      min-width: 0;
    }

    th, td {
      padding: 12px 12px;
      text-align: left;
      border-bottom: 1px solid rgba(41, 68, 57, 0.08);
      vertical-align: top;
      font-size: 15px;
      font-weight: 700;
    }

    th {
      position: sticky;
      top: 0;
      background: rgba(245, 248, 246, 0.98);
      color: var(--muted);
      font-size: 13px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      z-index: 50;
      box-shadow: 0 1px 0 rgba(41, 68, 57, 0.08);
    }

    thead th {
      position: sticky;
      top: 0;
      z-index: 50;
    }

    td.mono {
      font-family: inherit;
      font-size: 15px;
      line-height: 1.45;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      word-break: normal;
    }

    td.amount {
      font-family: inherit;
      font-variant-numeric: normal;
      font-weight: 700;
      white-space: nowrap;
      font-size: 15px;
    }

    td.fee {
      font-family: inherit;
      font-variant-numeric: normal;
      font-size: 15px;
      white-space: nowrap;
      font-weight: 400;
    }

    td.tip-amount {
      font-weight: 400;
    }

    td.key-id {
      font-size: 15px;
    }

    td.key-amount {
      font-size: 15px;
    }

    .mono-link {
      color: inherit;
      text-decoration: none;
      border-bottom: none;
    }

    .mono-link:hover { text-decoration: none; }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    .pill.yes {
      color: #0c5b42;
      background: rgba(11, 122, 90, 0.11);
    }

    .pill.no {
      color: #7a6b52;
      background: rgba(157, 131, 74, 0.12);
    }

    .empty {
      padding: 26px;
      color: var(--muted);
      text-align: center;
      font-size: 14px;
    }

    .highlight-sig {
      background: rgba(255, 193, 7, 0.3);
      font-weight: 700;
      color: #f57f17;
      padding: 2px 6px;
      border-radius: 4px;
      border-left: 3px solid #f57f17;
    }

    .highlight-signer {
      background: rgba(76, 175, 80, 0.2);
      font-weight: 700;
      color: #1b5e20;
      padding: 2px 6px;
      border-radius: 4px;
      border-left: 3px solid #1b5e20;
    }

    .row-highlight-sig {
      background-color: #ffeb3b !important;
    }

    .row-highlight-signer {
      background-color: #e8f5e9 !important;
    }

    .row-failed td {
      color: var(--danger) !important;
    }

    .row-failed .mono-link {
      color: var(--danger) !important;
    }

    .row-selected {
      box-shadow: inset 0 0 0 2px rgba(13, 94, 120, 0.45);
      background-color: rgba(13, 94, 120, 0.08) !important;
    }

    .row-signer-selected {
      background-color: rgba(63, 81, 181, 0.12) !important;
    }

    .status-success {
      color: #4caf50;
      font-weight: bold;
    }

    .status-failed {
      color: #f44336;
      font-weight: bold;
    }

    @media (max-width: 1080px) {
      body { padding: 16px; }
      .grid,
      .summary {
        grid-template-columns: 1fr;
      }
      .form-row-cols {
        grid-template-columns: 1fr;
      }
      .control-grid {
        grid-template-columns: 1fr;
      }
      .actions {
        flex-direction: column;
        align-items: stretch;
      }
      .btn-submit-main {
        width: 100%;
        justify-content: center;
      }
      .panel,
      .hero {
        padding: 18px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero hero-query">
      <div class="hero-title-row">
        <div class="brand-mark" aria-hidden="true"></div>
        <div>
          <h1>区块链数据高级查询</h1>
          <p class="hero-lead">输入交易哈希或账户地址，快速检索关联池子及区块深度数据。</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <form id="search-form">
        <div class="form-row">
          <label class="field-label-row" for="signature">
            <span>交易哈希 <span class="lbl-en">(Transaction Hash)</span></span>
            <span class="info-tip" title="用于定位基准区块；可先识别关联池子。">i</span>
          </label>
          <div class="hash-input-row">
            <div class="input-icon-wrap">
              <span class="glyph-input" aria-hidden="true">⌗</span>
              <input id="signature" name="signature" value="nr7wQwf7JqKuLXFjUrA63doDzJddYjTA4RqbHaCkden6UTbah5WNYn3N6igiazf16hogXGUCPTXtH6N1xdbhn5m" placeholder="输入 Solana 交易签名" required />
            </div>
            <button class="primary btn-identify" id="detect-pools-btn" type="button">Q 识别池子</button>
          </div>
        </div>

        <div class="form-row">
          <div class="control-grid">
            <div class="control-col">
              <div class="field-block">
                <div class="field-stack">
                  <label for="window">上下区块数量</label>
                  <input id="window" name="window" type="number" min="0" max="300" value="1" required />
                </div>
                <span id="window-range-summary" class="field-note">当前查询范围：前 1 到 后 1 个区块。</span>
              </div>
              <div class="actions control-actions">
                <button class="primary btn-submit-main" id="submit-btn" type="submit">Q 开始查询</button>
                <button class="btn-link-clear" id="clear-btn" type="button" aria-label="清空结果">清空结果</button>
              </div>
            </div>

            <div class="control-col">
              <div class="field-block">
                <div class="field-stack">
                  <label for="accountAddress">账户池子</label>
                  <input id="accountAddress" name="accountAddress" value="BAcEPqUsF3bTC8bSrXMiK4zNfAqG54b7cufmvpcaLjbV" placeholder="可手动输入池子/账户地址" required />
                </div>
              </div>
              <div class="field-block">
                <div class="field-stack">
                  <label for="poolCandidates">候选池子</label>
                  <select id="poolCandidates" name="poolCandidates" disabled>
                    <option value="">识别到多个池子时可在此选择...</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      </form>

      <div id="status" class="status"></div>
      <div id="progress-wrap" class="progress-wrap"><div id="progress-bar" class="progress-bar"></div></div>
      <div id="summary"></div>
    </section>

    <section class="panel">
      <div id="render-count" class="render-count">0 个区块总共 0 条，符合条件 0 条</div>
      <div class="table-wrap">
        <div class="table-scroll">
        <table>
          <colgroup>
            <col style="width: 90px;">
            <col style="width: 70px;">
            <col style="width: 220px;">
            <col style="width: 170px;">
            <col style="width: 120px;">
            <col style="width: 95px;">
            <col style="width: 140px;">
            <col style="width: 140px;">
            <col style="width: 130px;">
            <col style="width: 90px;">
            <col style="width: 130px;">
          </colgroup>
          <thead>
            <tr>
              <th>区块号</th>
              <th>名次</th>
              <th>交易哈希</th>
              <th>签名钱包</th>
              <th>下注金额</th>
              <th>下注单位</th>
              <th>利润</th>
              <th>优先费</th>
              <th>Tip 金额</th>
              <th>状态</th>
              <th>钱包战绩</th>
            </tr>
          </thead>
          <tbody id="result-body">
            <tr><td colspan="11" class="empty">还没有查询结果。</td></tr>
          </tbody>
        </table>
        </div>
      </div>
      <div class="hint">
        <strong>下注金额说明：</strong>统一按“签名钱包在该交易中的首次向外转账金额”解析（仅识别 SPL Token transfer/transferChecked 与 System transfer）。创建账户租金与手续费不计入下注金额。重复次数表示该钱包在查询结果中出现的次数。
      </div>
    </section>
  </div>

  <script>
    const form = document.getElementById("search-form");
    const submitBtn = document.getElementById("submit-btn");
    const clearBtn = document.getElementById("clear-btn");
    const detectPoolsBtn = document.getElementById("detect-pools-btn");
    const statusEl = document.getElementById("status");
    const progressWrapEl = document.getElementById("progress-wrap");
    const progressBarEl = document.getElementById("progress-bar");
    const summaryEl = document.getElementById("summary");
    const renderCountEl = document.getElementById("render-count");
    const resultBody = document.getElementById("result-body");
    const accountAddressInput = document.getElementById("accountAddress");
    const poolCandidatesEl = document.getElementById("poolCandidates");
    const windowInput = document.getElementById("window");
    const windowRangeSummaryEl = document.getElementById("window-range-summary");
    let progressTimer = null;
    let progressValue = 0;

    function setStatus(message, type = "") {
      statusEl.textContent = message || "";
      statusEl.className = "status" + (type ? ` ${type}` : "");
    }

    function updateWindowRangeSummary() {
      if (!windowRangeSummaryEl || !windowInput) return;
      let n = parseInt(String(windowInput.value).trim(), 10);
      if (Number.isNaN(n) || n < 0) n = 0;
      if (n > 300) n = 300;
      windowRangeSummaryEl.textContent = `当前查询范围：前 ${n} 到 后 ${n} 个区块。`;
    }

    function startProgress() {
      progressValue = 6;
      progressBarEl.style.width = `${progressValue}%`;
      progressWrapEl.classList.add("show");
      if (progressTimer) clearInterval(progressTimer);
      progressTimer = setInterval(() => {
        // 只做平滑逼近，防止在请求未结束前到达 100%
        progressValue = Math.min(92, progressValue + (100 - progressValue) * 0.08);
        progressBarEl.style.width = `${progressValue}%`;
      }, 180);
    }

    function finishProgress() {
      if (progressTimer) {
        clearInterval(progressTimer);
        progressTimer = null;
      }
      progressValue = 100;
      progressBarEl.style.width = "100%";
      setTimeout(() => {
        progressWrapEl.classList.remove("show");
        progressBarEl.style.width = "0%";
      }, 260);
    }

    function resetPoolCandidates(message = "识别到多个池子时可在此选择…") {
      poolCandidatesEl.innerHTML = "";
      const option = document.createElement("option");
      option.value = "";
      option.textContent = message;
      poolCandidatesEl.appendChild(option);
      poolCandidatesEl.value = "";
      poolCandidatesEl.disabled = true;
    }

    function renderPoolCandidates(pools) {
      if (!Array.isArray(pools) || pools.length === 0) {
        resetPoolCandidates("没有识别到池子，你可以继续手动输入账户地址。");
        return;
      }

      resetPoolCandidates(
        pools.length > 1
          ? `已识别到 ${pools.length} 个池子，请在这里选择`
          : "已识别到 1 个池子。"
      );
      poolCandidatesEl.disabled = false;

      pools.forEach((pool) => {
        const option = document.createElement("option");
        option.value = pool.pool_address || "";
        option.textContent =
          pool.label
          || `${pool.display_name || pool.dex_name || "未知池子"} : ${pool.pool_address || "-"}`;
        option.dataset.displayName = pool.display_name || pool.dex_name || "池子";
        poolCandidatesEl.appendChild(option);
      });

      if (pools.length === 1 && pools[0].pool_address) {
        poolCandidatesEl.selectedIndex = 1;
        accountAddressInput.value = pools[0].pool_address;
        return;
      }
    }

    function renderSummary(data) {
      if (!data) {
        summaryEl.innerHTML = "";
        return;
      }

      summaryEl.innerHTML = `
        <div class="summary">
          <div class="metric">
            <div class="label">基准区块</div>
            <div class="value">${data.base_slot}</div>
          </div>
          <div class="metric">
            <div class="label">扫描范围</div>
            <div class="value range-value">${data.scanned_from} - ${data.scanned_to}</div>
          </div>
          <div class="metric">
            <div class="label">请求区块数</div>
            <div class="value">${data.requested_slots}</div>
          </div>
          <div class="metric">
            <div class="label">有效区块数</div>
            <div class="value">${data.available_blocks}</div>
          </div>
          <div class="metric">
            <div class="label">空 / 跳过区块</div>
            <div class="value">${data.unavailable_slots}</div>
          </div>
          <div class="metric">
            <div class="label">匹配交易数</div>
            <div class="value">${data.match_count}</div>
          </div>
        </div>
      `;
    }

    function renderRows(rows, inputSignature) {
      if (!rows || rows.length === 0) {
        resultBody.innerHTML = `<tr><td colspan="11" class="empty">这个范围内没有找到包含该账户地址的交易。</td></tr>`;
        return;
      }

      const sortedRows = [...rows].sort((a, b) => {
        const slotDiff = Number(a.slot || 0) - Number(b.slot || 0);
        if (slotDiff !== 0) return slotDiff;
        const rankA = Number(a.rank_in_block || Number.MAX_SAFE_INTEGER);
        const rankB = Number(b.rank_in_block || Number.MAX_SAFE_INTEGER);
        if (rankA !== rankB) return rankA - rankB;
        return String(a.signature || "").localeCompare(String(b.signature || ""));
      });

      // 找出输入哈希对应的签名钱包
      let inputSignerWallet = null;
      for (const row of sortedRows) {
        if (row.signature.toLowerCase() === inputSignature.toLowerCase()) {
          inputSignerWallet = row.signer;
          break;
        }
      }

      // 统计每个钱包的成功/失败战绩
      const signerStats = {};
      sortedRows.forEach((row) => {
        if (row.signer) {
          if (!signerStats[row.signer]) {
            signerStats[row.signer] = { success: 0, failed: 0 };
          }
          if (row.success) {
            signerStats[row.signer].success += 1;
          } else {
            signerStats[row.signer].failed += 1;
          }
        }
      });

      function shortText(text) {
        if (!text) return "-";
        return text.slice(0, 14);
      }

      function shortPrefix(text) {
        if (!text) return "-";
        return text.slice(0, 14);
      }

      resultBody.innerHTML = sortedRows.map((row, index) => {
        // 判断是否应该高亮这一行
        const isInputRow = row.signature.toLowerCase() === inputSignature.toLowerCase();
        const isSameSignerAsInput = inputSignerWallet && row.signer === inputSignerWallet;
        const highlightClass = isInputRow ? 'row-highlight-sig' : (isSameSignerAsInput && !isInputRow ? 'row-highlight-signer' : '');
        const rowClass = `${highlightClass}${row.success ? '' : ' row-failed'}`.trim();

        const stats = row.signer ? signerStats[row.signer] : null;
        const walletRecord = stats ? `成 ${stats.success} / 败 ${stats.failed}` : "-";
        
        // 输出调试信息到console
        if (row.bet_amount === "-" && row.bet_amount_debug) {
          console.warn(`❌ 第 ${index + 1} 行无下注金额 - Signature: ${row.signature.substring(0, 10)}...`);
          console.table(row.bet_amount_debug);
        }

        return `
          <tr class="${rowClass}" data-row-index="${index}" style="cursor: pointer;" title="点击查看下注金额调试信息">
            <td>${row.slot}</td>
            <td>${row.rank_in_block ?? "-"}</td>
            <td class="mono key-id">
              <a class="mono-link" href="https://solscan.io/tx/${row.signature}" target="_blank" rel="noopener noreferrer">${shortText(row.signature)}</a>
            </td>
            <td class="mono key-id">
              ${row.signer ? `<a class="mono-link" href="https://solscan.io/account/${row.signer}" target="_blank" rel="noopener noreferrer">${shortPrefix(row.signer)}</a>` : "-"}
            </td>
            <td class="amount key-amount">${row.bet_amount}</td>
            <td>${row.bet_unit || "-"}</td>
            <td class="amount key-amount">${row.profit}</td>
            <td class="fee">${row.priority_fee}</td>
            <td class="tip-amount">${row.tip_amount}</td>
            <td class="status-cell" data-signer="${row.signer || ""}">${row.success ? '成功' : '失败'}</td>
            <td class="wallet-record-cell" data-signer="${row.signer || ""}">${walletRecord}</td>
          </tr>
        `;
      }).join("");
      
      // 点击“成败/钱包战绩”单元格时，标注同签名钱包的全部交易行
      document.querySelectorAll("tbody td.wallet-record-cell, tbody td.status-cell").forEach((cell) => {
        cell.addEventListener("click", (event) => {
          event.stopPropagation();
          const rowEl = cell.closest("tr[data-row-index]");
          const signer = cell.dataset.signer || "";
          const alreadySelected = rowEl?.classList.contains("row-signer-selected");

          // 同步当前行选中态
          document.querySelectorAll("tbody tr[data-row-index]").forEach((r) => {
            r.classList.remove("row-selected");
          });
          if (rowEl) {
            rowEl.classList.add("row-selected");
          }

          document.querySelectorAll("tbody tr[data-row-index]").forEach((rowEl) => {
            rowEl.classList.remove("row-signer-selected");
          });
          if (!alreadySelected && signer) {
            document.querySelectorAll("tbody tr[data-row-index]").forEach((rowEl) => {
              const idx = Number(rowEl.getAttribute("data-row-index"));
              const rowData = sortedRows[idx];
              if (rowData?.signer === signer) {
                rowEl.classList.add("row-signer-selected");
              }
            });
          }
        });
      });

      // 为所有行添加点击事件来显示debug信息
      document.querySelectorAll("tbody tr[data-row-index]").forEach((tr, idx) => {
        tr.addEventListener("click", () => {
          // 普通点击选中行时，清掉“同钱包批量标注”
          document.querySelectorAll("tbody tr[data-row-index]").forEach((rowEl) => {
            rowEl.classList.remove("row-signer-selected");
          });

          document.querySelectorAll("tbody tr[data-row-index]").forEach((rowEl) => {
            rowEl.classList.remove("row-selected");
          });
          tr.classList.add("row-selected");

          const row = sortedRows[idx];
          if (row.bet_amount_debug) {
            console.log(`📊 第 ${idx + 1} 行的下注金额调试信息:`);
            console.table(row.bet_amount_debug);
          }
        });
      });

      // 点击表格空白区域时，清掉“同钱包批量标注”
      const tableScroll = document.querySelector(".table-scroll");
      if (tableScroll) {
        tableScroll.addEventListener("click", (event) => {
          const row = event.target.closest("tr[data-row-index]");
          if (!row) {
            document.querySelectorAll("tbody tr[data-row-index]").forEach((rowEl) => {
              rowEl.classList.remove("row-signer-selected");
            });
          }
        });
      }
    }

    async function handleSubmit(event) {
      event.preventDefault();
      const payload = {
        signature: document.getElementById("signature").value.trim(),
        account_address: accountAddressInput.value.trim(),
        window: Number(windowInput.value),
      };

      submitBtn.disabled = true;
      setStatus("正在查询附近区块，请稍等...", "loading");
      startProgress();

      try {
        const response = await fetch("api/search", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "查询失败");
        }

        renderSummary(data.summary);
        renderRows(data.rows, payload.signature);
        renderCountEl.textContent = `${data.summary.requested_slots} 个区块总共 ${data.summary.total_transactions} 条，符合条件 ${data.summary.match_count} 条`;
        const allBetMissing = (data.rows || []).length > 0 && data.rows.every((row) => row.bet_amount === "-");
        if (allBetMissing) {
          setStatus(`查询完成，共找到 ${data.summary.match_count} 笔匹配交易。当前输入地址未在这些交易的 token 余额快照中产生可解析变化，下注金额显示为 "-"。`, "warn");
        } else {
          setStatus(`查询完成，共找到 ${data.summary.match_count} 笔匹配交易。`);
        }
      } catch (error) {
        renderSummary(null);
        renderRows([]);
        setStatus(error.message || "查询失败", "error");
      } finally {
        finishProgress();
        submitBtn.disabled = false;
      }
    }

    async function handleDetectPools() {
      accountAddressInput.value = "";
      resetPoolCandidates();

      const signature = document.getElementById("signature").value.trim();
      if (!signature) {
        setStatus("请先输入交易哈希。", "error");
        return;
      }

      detectPoolsBtn.disabled = true;
      setStatus("正在根据交易哈希识别池子...", "loading");

      try {
        const response = await fetch("api/pools", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ signature }),
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "池子识别失败");
        }

        renderPoolCandidates(data.pools || []);
        if (!data.pools || data.pools.length === 0) {
          setStatus("没有识别到池子，请继续手动输入账户地址。", "warn");
        } else if (data.pools.length === 1) {
          setStatus("已识别到 1 个池子，并自动填入账户地址。");
        } else {
          setStatus(`已识别到 ${data.pools.length} 个池子，请从下拉框选择。`);
        }
      } catch (error) {
        resetPoolCandidates("识别池子失败");
        setStatus(error.message || "池子识别失败", "error");
      } finally {
        detectPoolsBtn.disabled = false;
      }
    }

    windowInput.addEventListener("input", updateWindowRangeSummary);
    windowInput.addEventListener("change", updateWindowRangeSummary);
    updateWindowRangeSummary();

    form.addEventListener("submit", handleSubmit);
    detectPoolsBtn.addEventListener("click", handleDetectPools);
    poolCandidatesEl.addEventListener("change", (event) => {
      const value = event.target.value || "";
      if (!value) {
        return;
      }
      accountAddressInput.value = value;
    });
    clearBtn.addEventListener("click", () => {
      form.reset();
      windowInput.value = 1;
      accountAddressInput.value = "";
      resetPoolCandidates();
      updateWindowRangeSummary();
      renderSummary(null);
      resultBody.innerHTML = `<tr><td colspan="11" class="empty">还没有查询结果。</td></tr>`;
      renderCountEl.textContent = "0 个区块总共 0 条，符合条件 0 条";
      setStatus("");
    });
  </script>
</body>
</html>
"""


class SearchError(Exception):
    pass


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def load_tip_accounts(path: Path) -> dict[str, set[str]]:
    providers: dict[str, set[str]] = {}
    current_provider: str | None = None
    if not path.exists():
        return providers

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line in {"helius", "jito", "nextblock", "astra", "stellium"}:
            current_provider = line
            providers[current_provider] = set()
            continue
        if current_provider is not None:
            providers[current_provider].add(line)
    return providers


def build_rpc_url(env: dict[str, str]) -> str:
    helius_api_key = env.get("HELIUS_API_KEY") or os.environ.get("HELIUS_API_KEY", "").strip()

    candidates = [
        env.get("HELIUS_RPC_URL"),
        env.get("EXECUTION_SEND_LANE_RPC_1_ENDPOINT"),
        env.get("EXECUTION_SEND_LANE_RPC_2_ENDPOINT"),
        env.get("EXECUTION_SEND_LANE_RPC_3_ENDPOINT"),
        env.get("EXECUTION_SEND_LANE_RPC_4_ENDPOINT"),
        env.get("EXECUTION_SEND_LANE_RPC_5_ENDPOINT"),
    ]

    for candidate in candidates:
        if not candidate:
            continue
        rpc_url = candidate.strip()
        if helius_api_key and "helius" in rpc_url and "api-key=" not in rpc_url:
            separator = "&" if "?" in rpc_url else "?"
            rpc_url = f"{rpc_url}{separator}api-key={helius_api_key}"
        return rpc_url

    return PUBLIC_RPC_URL


def sanitize_rpc_url(url: str) -> str:
    parts = urlsplit(url)
    query_items = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if "key" in key.lower() or "token" in key.lower():
            query_items.append((key, "***"))
        else:
            query_items.append((key, value))
    safe_query = urlencode(query_items)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, parts.fragment))


def decimal_from_amount(raw_amount: str | int | None, decimals: int | None) -> Decimal:
    if raw_amount in (None, ""):
        return Decimal("0")
    if decimals is None:
        decimals = 0
    return Decimal(str(raw_amount)) / (Decimal(10) ** int(decimals))


def format_decimal(value: Decimal | None, decimals: int = 9) -> str:
    if value is None:
        return "-"
    quant = Decimal(1) / (Decimal(10) ** decimals)
    try:
        normalized = value.quantize(quant).normalize()
    except InvalidOperation:
        normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def short_account_list(accounts: list[str], max_items: int = 2) -> str:
    if not accounts:
        return "-"
    short_accounts = [account[:12] for account in accounts[:max_items]]
    if len(accounts) <= max_items:
        return ", ".join(short_accounts)
    preview = ", ".join(short_accounts)
    return f"{preview} 等{len(accounts)}个"


def recursive_contains(target: str, payload: Any) -> bool:
    if isinstance(payload, str):
        return payload == target
    if isinstance(payload, list):
        return any(recursive_contains(target, item) for item in payload)
    if isinstance(payload, dict):
        return any(recursive_contains(target, value) for value in payload.values())
    return False


def as_json_dict(value: Any) -> dict[str, Any]:
    """Helius/jsonParsed 下 parsed、info、uiTokenAmount 等偶发为字符串，避免对 str 调 .get。"""
    return value if isinstance(value, dict) else {}


def parse_signer_wallet(message: dict[str, Any]) -> str | None:
    account_keys = message.get("accountKeys") or []
    if not account_keys:
        return None

    first = account_keys[0]
    if isinstance(first, dict):
        for item in account_keys:
            if item.get("signer"):
                return item.get("pubkey")
        return first.get("pubkey")

    header = message.get("header") or {}
    num_required = int(header.get("numRequiredSignatures", 0))
    if num_required > 0:
        return account_keys[0]
    return account_keys[0]


def iter_all_instructions(raw_tx: dict[str, Any]) -> list[dict[str, Any]]:
    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    meta = raw_tx.get("meta") or {}
    instructions: list[dict[str, Any]] = []

    for ix in message.get("instructions") or []:
        if isinstance(ix, dict):
            instructions.append(ix)

    for group in meta.get("innerInstructions") or []:
        for ix in group.get("instructions") or []:
            if isinstance(ix, dict):
                instructions.append(ix)

    return instructions


def iter_instructions_in_execution_order(raw_tx: dict[str, Any]) -> list[dict[str, Any]]:
    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    meta = raw_tx.get("meta") or {}
    ordered: list[dict[str, Any]] = []
    outer = message.get("instructions") or []
    inner_groups = {int(group.get("index", -1)): group.get("instructions") or [] for group in meta.get("innerInstructions") or []}
    for idx, ix in enumerate(outer):
        if isinstance(ix, dict):
            ordered.append(ix)
        for inner_ix in inner_groups.get(idx, []):
            if isinstance(inner_ix, dict):
                ordered.append(inner_ix)
    return ordered


def transaction_mentions_token(raw_tx: dict[str, Any], token_mint: str) -> bool:
    meta = raw_tx.get("meta") or {}

    for balance in meta.get("preTokenBalances") or []:
        if balance.get("mint") == token_mint:
            return True
    for balance in meta.get("postTokenBalances") or []:
        if balance.get("mint") == token_mint:
            return True

    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    if recursive_contains(token_mint, message.get("accountKeys") or []):
        return True

    for ix in iter_all_instructions(raw_tx):
        if recursive_contains(token_mint, ix):
            return True

    return False


@lru_cache(maxsize=None)
def anchor_discriminator(account_name: str) -> bytes:
    seed = f"account:{account_name}".encode("utf-8")
    return hashlib.sha256(seed).digest()[:8]


def extract_account_key(raw_key: Any) -> str | None:
    if isinstance(raw_key, str):
        return raw_key
    if isinstance(raw_key, dict):
        pubkey = raw_key.get("pubkey")
        if isinstance(pubkey, str):
            return pubkey
    return None


def resolve_account_keys(raw_tx: dict[str, Any]) -> list[str]:
    transaction = raw_tx.get("transaction") or {}
    message = transaction.get("message") or {}
    meta = raw_tx.get("meta") or {}

    account_keys: list[str] = []
    for raw_key in message.get("accountKeys") or []:
        key = extract_account_key(raw_key)
        if key is not None:
            account_keys.append(key)

    loaded_addresses = meta.get("loadedAddresses") or {}
    for section in ("writable", "readonly"):
        for raw_key in loaded_addresses.get(section) or []:
            key = extract_account_key(raw_key)
            if key is not None:
                account_keys.append(key)

    return account_keys


def resolve_instruction(
    raw_instruction: Any, account_keys: list[str]
) -> ResolvedInstruction | None:
    if not isinstance(raw_instruction, dict):
        return None

    program_id_index = raw_instruction.get("programIdIndex")
    account_indices = raw_instruction.get("accounts")
    if not isinstance(program_id_index, int) or not isinstance(account_indices, list):
        return None
    if program_id_index < 0 or program_id_index >= len(account_keys):
        return None

    accounts: list[str] = []
    for raw_index in account_indices:
        if not isinstance(raw_index, int) or raw_index < 0 or raw_index >= len(account_keys):
            return None
        accounts.append(account_keys[raw_index])

    return ResolvedInstruction(
        program_id=account_keys[program_id_index],
        accounts=accounts,
    )


def iter_resolved_instructions(raw_tx: dict[str, Any]) -> list[ResolvedInstruction]:
    transaction = raw_tx.get("transaction") or {}
    message = transaction.get("message") or {}
    meta = raw_tx.get("meta") or {}
    account_keys = resolve_account_keys(raw_tx)

    top_level_instructions = message.get("instructions") or []
    inner_by_index: dict[int, list[Any]] = {}
    for group in meta.get("innerInstructions") or []:
        if not isinstance(group, dict):
            continue
        index = group.get("index")
        instructions = group.get("instructions")
        if isinstance(index, int) and isinstance(instructions, list):
            inner_by_index[index] = instructions

    resolved: list[ResolvedInstruction] = []
    for index, raw_instruction in enumerate(top_level_instructions):
        instruction = resolve_instruction(raw_instruction, account_keys)
        if instruction is not None:
            resolved.append(instruction)

        for inner_instruction in inner_by_index.get(index, []):
            instruction = resolve_instruction(inner_instruction, account_keys)
            if instruction is not None:
                resolved.append(instruction)

    return resolved


def collect_candidate_accounts(raw_tx: dict[str, Any]) -> list[str]:
    candidate_accounts: list[str] = []
    seen_accounts: set[str] = set()

    for instruction in iter_resolved_instructions(raw_tx):
        for account in instruction.accounts:
            if account in seen_accounts:
                continue
            seen_accounts.add(account)
            candidate_accounts.append(account)

    return candidate_accounts


def decode_account_data(account_info: dict[str, Any] | None) -> bytes | None:
    if not isinstance(account_info, dict):
        return None

    data = account_info.get("data")
    if not isinstance(data, list) or len(data) < 2 or data[1] != "base64":
        return None

    encoded = data[0]
    if not isinstance(encoded, str):
        return None

    try:
        return base64.b64decode(encoded)
    except ValueError:
        return None


def base58_encode(raw: bytes) -> str:
    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    num = int.from_bytes(raw, "big")

    if num == 0:
        return "1" * leading_zeroes or "1"

    chars: list[str] = []
    while num > 0:
        num, remainder = divmod(num, 58)
        chars.append(BASE58_ALPHABET[remainder])

    return "1" * leading_zeroes + "".join(reversed(chars))


def base58_decode(value: str) -> bytes | None:
    num = 0
    try:
        for char in value:
            num = (num * 58) + BASE58_INDEX[char]
    except KeyError:
        return None

    decoded = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading_zeroes) + decoded


def is_ed25519_point(encoded: bytes) -> bool:
    if len(encoded) != 32:
        return False

    y = int.from_bytes(encoded, "little")
    x_sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED25519_FIELD_PRIME:
        return False

    y_squared = (y * y) % ED25519_FIELD_PRIME
    numerator = (y_squared - 1) % ED25519_FIELD_PRIME
    denominator = (ED25519_D * y_squared + 1) % ED25519_FIELD_PRIME
    if denominator == 0:
        return False

    x_squared = (numerator * pow(denominator, ED25519_FIELD_PRIME - 2, ED25519_FIELD_PRIME)) % ED25519_FIELD_PRIME
    x = pow(x_squared, (ED25519_FIELD_PRIME + 3) // 8, ED25519_FIELD_PRIME)
    if (x * x - x_squared) % ED25519_FIELD_PRIME != 0:
        x = (x * ED25519_SQRT_M1) % ED25519_FIELD_PRIME
    if (x * x - x_squared) % ED25519_FIELD_PRIME != 0:
        return False
    if x == 0 and x_sign == 1:
        return False

    return True


def find_program_address(seeds: list[bytes], program_id: bytes) -> bytes | None:
    if len(program_id) != 32 or len(seeds) > 16 or any(len(seed) > 32 for seed in seeds):
        return None

    for bump in range(255, -1, -1):
        hasher = hashlib.sha256()
        for seed in (*seeds, bytes([bump])):
            hasher.update(seed)
        hasher.update(program_id)
        hasher.update(PDA_MARKER)
        candidate = hasher.digest()
        if not is_ed25519_point(candidate):
            return candidate

    return None


def read_pubkey(data: bytes, offset: int) -> str | None:
    end = offset + 32
    if offset < 0 or end > len(data):
        return None
    return base58_encode(data[offset:end])


def read_optional_pubkey(data: bytes, offset: int) -> str | None:
    end = offset + 32
    if offset < 0 or end > len(data):
        return None

    raw = data[offset:end]
    if not any(raw):
        return None
    return base58_encode(raw)


def decode_borsh_string(data: bytes, offset: int) -> tuple[str | None, int]:
    if offset + 4 > len(data):
        return None, offset

    length = int.from_bytes(data[offset : offset + 4], "little")
    start = offset + 4
    end = start + length
    if end > len(data):
        return None, offset

    try:
        value = data[start:end].decode("utf-8", "ignore").rstrip("\x00").strip()
    except ValueError:
        return None, offset

    return value, end


def decode_token_metadata_symbol_bytes(data: bytes, expected_mint: str | None = None) -> str | None:
    candidate_offsets = (0,)
    if data.startswith(TOKEN_METADATA_INTERFACE_DISCRIMINATOR):
        candidate_offsets = (8, 0)

    for struct_offset in candidate_offsets:
        if len(data) < struct_offset + 64:
            continue

        if expected_mint is not None:
            mint = read_pubkey(data, struct_offset + 32)
            if mint != expected_mint:
                continue

        offset = struct_offset + 64
        _, offset = decode_borsh_string(data, offset)
        symbol, _ = decode_borsh_string(data, offset)
        if symbol:
            return symbol

    return None


def iter_token_2022_mint_tlv_entries(data: bytes) -> list[tuple[int, bytes]]:
    if len(data) <= TOKEN_2022_MINT_SIZE:
        return []
    if len(data) < TOKEN_2022_TLV_START:
        return []
    if any(data[TOKEN_2022_MINT_SIZE:TOKEN_2022_PADDING_END]):
        return []
    if data[TOKEN_2022_MINT_ACCOUNT_TYPE_OFFSET] != TOKEN_2022_MINT_ACCOUNT_TYPE:
        return []

    entries: list[tuple[int, bytes]] = []
    offset = TOKEN_2022_TLV_START
    while offset + 4 <= len(data):
        extension_type = int.from_bytes(data[offset : offset + 2], "little")
        extension_len = int.from_bytes(data[offset + 2 : offset + 4], "little")
        offset += 4

        if extension_type == 0:
            break

        end = offset + extension_len
        if end > len(data):
            return []

        entries.append((extension_type, data[offset:end]))
        offset = end

    return entries


def parse_token_2022_mint_metadata(
    mint: str, account_info: dict[str, Any] | None
) -> tuple[str | None, str | None]:
    if not isinstance(account_info, dict) or account_info.get("owner") != TOKEN_2022_PROGRAM_ID:
        return None, None

    data = decode_account_data(account_info)
    if data is None:
        return None, None

    symbol: str | None = None
    pointer_target: str | None = None
    for extension_type, extension_data in iter_token_2022_mint_tlv_entries(data):
        if extension_type == TOKEN_2022_TOKEN_METADATA_EXTENSION and symbol is None:
            symbol = decode_token_metadata_symbol_bytes(extension_data, mint)
        elif extension_type == TOKEN_2022_METADATA_POINTER_EXTENSION and pointer_target is None:
            pointer_target = read_optional_pubkey(extension_data, 32)

    return symbol, pointer_target


def decode_token_metadata_account_symbol(
    account_info: dict[str, Any] | None, expected_mint: str
) -> str | None:
    data = decode_account_data(account_info)
    if data is None:
        return None
    return decode_token_metadata_symbol_bytes(data, expected_mint)


def is_pool_account(program_id: str, account_info: dict[str, Any] | None) -> bool:
    spec = DEX_PROGRAMS.get(program_id)
    if spec is None or not isinstance(account_info, dict):
        return False
    if account_info.get("owner") != program_id:
        return False

    data = decode_account_data(account_info)
    if data is None:
        return False

    if spec.anchor_account_name is not None:
        if len(data) < 8 or data[:8] != anchor_discriminator(spec.anchor_account_name):
            return False

    if spec.layout_validator is not None and not spec.layout_validator(data):
        return False

    return True


def detect_pool(account_info: dict[str, Any] | None) -> tuple[str, DexProgramSpec] | None:
    if not isinstance(account_info, dict):
        return None

    owner = account_info.get("owner")
    if not isinstance(owner, str):
        return None

    spec = DEX_PROGRAMS.get(owner)
    if spec is None:
        return None

    if not is_pool_account(owner, account_info):
        return None

    return owner, spec


def extract_pool_mints(program_id: str, account_info: dict[str, Any] | None) -> tuple[str, str] | None:
    spec = DEX_PROGRAMS.get(program_id)
    if spec is None or spec.mint_a_offset is None or spec.mint_b_offset is None:
        return None

    data = decode_account_data(account_info)
    if data is None:
        return None

    mint_a = read_pubkey(data, spec.mint_a_offset)
    mint_b = read_pubkey(data, spec.mint_b_offset)
    if mint_a is None or mint_b is None:
        return None

    return mint_a, mint_b


def find_metadata_pda(mint: str) -> str | None:
    if SoldersPubkey is not None:
        try:
            metadata_program = SoldersPubkey.from_string(METADATA_PROGRAM_ID)
            mint_pubkey = SoldersPubkey.from_string(mint)
        except ValueError:
            return None

        metadata_pda, _ = SoldersPubkey.find_program_address(
            [b"metadata", bytes(metadata_program), bytes(mint_pubkey)],
            metadata_program,
        )
        return str(metadata_pda)

    metadata_program = base58_decode(METADATA_PROGRAM_ID)
    mint_pubkey = base58_decode(mint)
    if metadata_program is None or mint_pubkey is None:
        return None

    metadata_pda = find_program_address([b"metadata", metadata_program, mint_pubkey], metadata_program)
    if metadata_pda is None:
        return None

    return base58_encode(metadata_pda)


def decode_metadata_symbol(account_info: dict[str, Any] | None) -> str | None:
    if not isinstance(account_info, dict):
        return None
    if account_info.get("owner") != METADATA_PROGRAM_ID:
        return None

    data = decode_account_data(account_info)
    if data is None or len(data) < 69:
        return None

    offset = 1 + 32 + 32
    _, offset = decode_borsh_string(data, offset)
    symbol, _ = decode_borsh_string(data, offset)
    return symbol or None


def resolve_symbols(
    mints: list[str],
    fetch_accounts: Callable[[list[str]], dict[str, dict[str, Any] | None]],
) -> dict[str, str]:
    symbols: dict[str, str] = {WRAPPED_SOL_MINT: "SOL"}

    unique_mints = list(dict.fromkeys(mint for mint in mints if mint and mint not in symbols))
    if not unique_mints:
        return symbols

    lookup_targets = list(unique_mints)
    mint_to_metadata_pda: dict[str, str] = {}
    seen_targets = set(lookup_targets)
    for mint in unique_mints:
        metadata_pda = find_metadata_pda(mint)
        if metadata_pda is None:
            continue
        mint_to_metadata_pda[mint] = metadata_pda
        if metadata_pda in seen_targets:
            continue
        seen_targets.add(metadata_pda)
        lookup_targets.append(metadata_pda)

    lookup_infos = fetch_accounts(lookup_targets)

    pointer_targets: dict[str, list[str]] = {}
    for mint in unique_mints:
        metadata_pda = mint_to_metadata_pda.get(mint)
        if metadata_pda is not None:
            symbol = decode_metadata_symbol(lookup_infos.get(metadata_pda))
            if symbol:
                symbols[mint] = symbol
                continue

        inline_symbol, pointer_target = parse_token_2022_mint_metadata(mint, lookup_infos.get(mint))
        if inline_symbol:
            symbols[mint] = inline_symbol
            continue

        if pointer_target is None or pointer_target == mint:
            continue

        if pointer_target in lookup_infos:
            symbol = decode_metadata_symbol(lookup_infos.get(pointer_target))
            if symbol is None:
                symbol = decode_token_metadata_account_symbol(lookup_infos.get(pointer_target), mint)
            if symbol:
                symbols[mint] = symbol
            continue

        pointer_targets.setdefault(pointer_target, []).append(mint)

    if not pointer_targets:
        return symbols

    pointer_infos = fetch_accounts(list(pointer_targets))
    for pointer_target, related_mints in pointer_targets.items():
        account_info = pointer_infos.get(pointer_target)
        metaplex_symbol = decode_metadata_symbol(account_info)
        for mint in related_mints:
            symbol = metaplex_symbol or decode_token_metadata_account_symbol(account_info, mint)
            if symbol:
                symbols[mint] = symbol
                break

    return symbols


def find_pools(
    raw_tx: dict[str, Any],
    fetch_accounts: Callable[[list[str]], dict[str, dict[str, Any] | None]],
) -> list[PoolInfo]:
    candidate_accounts = collect_candidate_accounts(raw_tx)
    if not candidate_accounts:
        return []

    account_infos = fetch_accounts(candidate_accounts)

    pools: list[PoolInfo] = []
    seen_pools: set[str] = set()
    for account in candidate_accounts:
        detected = detect_pool(account_infos.get(account))
        if detected is None or account in seen_pools:
            continue

        program_id, spec = detected
        mint_pair = extract_pool_mints(program_id, account_infos.get(account))
        if mint_pair is None:
            continue

        mint_a, mint_b = mint_pair
        seen_pools.add(account)
        pools.append(
            PoolInfo(
                dex_name=spec.dex_name,
                pool_address=account,
                mint_a=mint_a,
                mint_b=mint_b,
            )
        )

    symbol_by_mint = resolve_symbols([pool.mint_a for pool in pools] + [pool.mint_b for pool in pools], fetch_accounts)
    return [
        PoolInfo(
            dex_name=pool.dex_name,
            pool_address=pool.pool_address,
            mint_a=pool.mint_a,
            mint_b=pool.mint_b,
            symbol_a=symbol_by_mint.get(pool.mint_a),
            symbol_b=symbol_by_mint.get(pool.mint_b),
        )
        for pool in pools
    ]


def format_symbol(symbol: str | None) -> str:
    return symbol or "未知符号"


def format_dex_name(dex_name: str) -> str:
    return dex_name.removesuffix(" Program")


@dataclass
class BetAmountResult:
    display: str
    raw_delta: Decimal | None
    source: str
    unit: str | None = None
    debug_info: dict | None = None


def token_symbol(mint: str | None) -> str:
    if not mint:
        return "TOKEN"
    known = {
        "So11111111111111111111111111111111111111112": "SOL",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC",
        "Es9vMFrzaCERmJfrF4H2FYD4KCoA5f92x5xkLZK4j8h": "USDT",
    }
    return known.get(mint, mint[:6])


def first_wallet_outbound_amount(raw_tx: dict[str, Any], wallet: str | None) -> BetAmountResult | None:
    if not wallet:
        return None
    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    meta = raw_tx.get("meta") or {}
    account_keys = message.get("accountKeys") or []

    def key_at(index: int) -> str | None:
        if index < 0 or index >= len(account_keys):
            return None
        key = account_keys[index]
        if isinstance(key, dict):
            return key.get("pubkey")
        return key

    token_account_meta: dict[str, tuple[str | None, int | None]] = {}
    for entry in (meta.get("preTokenBalances") or []) + (meta.get("postTokenBalances") or []):
        idx = entry.get("accountIndex")
        if not isinstance(idx, int):
            continue
        pubkey = key_at(idx)
        if not pubkey:
            continue
        ui = as_json_dict(entry.get("uiTokenAmount"))
        decimals = ui.get("decimals")
        token_account_meta[pubkey] = (
            entry.get("mint"),
            int(decimals) if decimals is not None else None,
        )

    first_spl: BetAmountResult | None = None
    for ix in iter_instructions_in_execution_order(raw_tx):
        program = ix.get("program")
        parsed = as_json_dict(ix.get("parsed"))
        ix_type = parsed.get("type")
        info = as_json_dict(parsed.get("info"))
        source = info.get("source")
        destination = info.get("destination")
        authority = info.get("authority") or info.get("owner")
        mint = info.get("mint")

        # SPL Token 转账：authority 是目标钱包，且转给了其他账户
        if program == "spl-token" and ix_type in {"transfer", "transferChecked"}:
            if authority != wallet or not source or not destination or source == destination:
                continue
            token_amount = as_json_dict(info.get("tokenAmount"))
            if isinstance(token_amount, dict):
                ui_amount = token_amount.get("uiAmountString")
                decimals = token_amount.get("decimals")
                if ui_amount not in (None, ""):
                    symbol = token_symbol(mint)
                    first_spl = BetAmountResult(
                        display=f"{ui_amount} {symbol}",
                        raw_delta=Decimal(str(ui_amount)),
                        source="first_signer_outbound_spl",
                        unit=symbol,
                        debug_info={
                            "source": "first_signer_outbound_spl",
                            "program": program,
                            "type": ix_type,
                            "mint": mint,
                            "authority": authority,
                            "from": source,
                            "to": destination,
                        },
                    )
                    break
                raw_amount = info.get("amount")
                if raw_amount not in (None, "") and decimals is not None:
                    amount = decimal_from_amount(str(raw_amount), int(decimals))
                    symbol = token_symbol(mint)
                    first_spl = BetAmountResult(
                        display=f"{format_decimal(amount, decimals=9)} {symbol}",
                        raw_delta=amount,
                        source="first_signer_outbound_spl",
                        unit=symbol,
                        debug_info={
                            "source": "first_signer_outbound_spl",
                            "program": program,
                            "type": ix_type,
                            "mint": mint,
                            "authority": authority,
                            "from": source,
                            "to": destination,
                        },
                    )
                    break
            raw_amount = info.get("amount")
            if raw_amount not in (None, ""):
                inferred_mint, inferred_decimals = token_account_meta.get(source, (mint, None))
                if inferred_decimals is not None:
                    amount = decimal_from_amount(str(raw_amount), inferred_decimals)
                    symbol = token_symbol(inferred_mint)
                    first_spl = BetAmountResult(
                        display=f"{format_decimal(amount, decimals=9)} {symbol}",
                        raw_delta=amount,
                        source="first_signer_outbound_spl",
                        unit=symbol,
                        debug_info={
                            "source": "first_signer_outbound_spl",
                            "program": program,
                            "type": ix_type,
                            "mint": inferred_mint,
                            "authority": authority,
                            "from": source,
                            "to": destination,
                        },
                    )
                    break

    if first_spl is not None:
        return first_spl
    return None


def address_acts_as_transfer_wallet(raw_tx: dict[str, Any], address: str) -> bool:
    for ix in iter_instructions_in_execution_order(raw_tx):
        parsed = as_json_dict(ix.get("parsed"))
        info = as_json_dict(parsed.get("info"))
        ix_type = parsed.get("type")
        program = ix.get("program")
        if program == "spl-token" and ix_type in {"transfer", "transferChecked"}:
            if (info.get("authority") or info.get("owner")) == address:
                return True
        if program == "system" and ix_type == "transfer":
            if info.get("source") == address:
                return True
    return False


def compute_bet_amount(raw_tx: dict[str, Any], token_mint: str, signer: str | None) -> BetAmountResult:
    """唯一口径：签名钱包在该交易中的首次向外付出金额"""
    meta = raw_tx.get("meta") or {}
    
    # 调试信息
    debug = {
        "token_mint": token_mint,
        "signer": signer[:20] if signer else None,
        "has_meta": bool(meta),
        "pre_balances_count": len(meta.get("preTokenBalances") or []),
        "post_balances_count": len(meta.get("postTokenBalances") or []),
        "mints_in_pre": [],
        "mints_in_post": [],
    }
    
    # 保留调试信息统计，便于在 UI 里查看为何某些交易只能退化到 fee
    pre_balances_by_owner: dict[str, Decimal] = {}
    post_balances_by_owner: dict[str, Decimal] = {}
    pre_balances_by_index: dict[int, tuple[Decimal, str | None]] = {}
    post_balances_by_index: dict[int, tuple[Decimal, str | None]] = {}
    
    for entry in meta.get("preTokenBalances") or []:
        mint = entry.get("mint")
        if mint not in debug["mints_in_pre"]:
            debug["mints_in_pre"].append(mint[:10] if mint else None)
        
        if mint != token_mint:
            continue
        owner = entry.get("owner")
        ui_amount = as_json_dict(entry.get("uiTokenAmount"))
        decimals = ui_amount.get("decimals", 0)
        amount = decimal_from_amount(ui_amount.get("amount"), decimals)
        if owner:
            pre_balances_by_owner[owner] = amount
        account_index = entry.get("accountIndex")
        if isinstance(account_index, int):
            pre_balances_by_index[account_index] = (amount, owner)
    
    for entry in meta.get("postTokenBalances") or []:
        mint = entry.get("mint")
        if mint not in debug["mints_in_post"]:
            debug["mints_in_post"].append(mint[:10] if mint else None)
        
        if mint != token_mint:
            continue
        owner = entry.get("owner")
        ui_amount = as_json_dict(entry.get("uiTokenAmount"))
        decimals = ui_amount.get("decimals", 0)
        amount = decimal_from_amount(ui_amount.get("amount"), decimals)
        if owner:
            post_balances_by_owner[owner] = amount
        account_index = entry.get("accountIndex")
        if isinstance(account_index, int):
            post_balances_by_index[account_index] = (amount, owner)
    
    debug["matched_owners_pre"] = len(pre_balances_by_owner)
    debug["matched_owners_post"] = len(post_balances_by_owner)
    debug["matched_accounts_pre"] = len(pre_balances_by_index)
    debug["matched_accounts_post"] = len(post_balances_by_index)
    
    primary_wallet = signer
    primary_source = "signer"
    # 防护策略：仅在 signer 无法解析且输入地址确实扮演转账钱包时，切换到输入地址。
    if primary_wallet and first_wallet_outbound_amount(raw_tx, primary_wallet) is None:
        if token_mint and token_mint != primary_wallet and address_acts_as_transfer_wallet(raw_tx, token_mint):
            primary_wallet = token_mint
            primary_source = "input_address_as_wallet"

    first_outbound = first_wallet_outbound_amount(raw_tx, primary_wallet)
    if first_outbound is not None:
        debug["source"] = first_outbound.source
        debug["wallet_select_source"] = primary_source
        debug["selected_wallet"] = primary_wallet[:20] if primary_wallet else None
        debug["fallback"] = first_outbound.debug_info
        return BetAmountResult(
            display=first_outbound.display,
            raw_delta=first_outbound.raw_delta,
            source=first_outbound.source,
            unit=first_outbound.unit,
            debug_info=debug,
        )

    debug["source"] = "not_found"
    return BetAmountResult(display="-", raw_delta=None, source="not_found", unit=None, debug_info=debug)


def extract_last_inbound_to_signer(
    raw_tx: dict[str, Any],
    signer: str | None,
    preferred_unit: str | None = None,
    outbound_amount: Decimal | None = None,
) -> BetAmountResult | None:
    if not signer:
        return None
    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    meta = raw_tx.get("meta") or {}
    account_keys = message.get("accountKeys") or []

    def key_at(index: int) -> str | None:
        if index < 0 or index >= len(account_keys):
            return None
        key = account_keys[index]
        if isinstance(key, dict):
            return key.get("pubkey")
        return key

    signer_token_accounts: set[str] = set()
    token_account_mint: dict[str, str] = {}
    token_account_decimals: dict[str, int] = {}
    for entry in (meta.get("preTokenBalances") or []) + (meta.get("postTokenBalances") or []):
        idx = entry.get("accountIndex")
        if not isinstance(idx, int):
            continue
        pubkey = key_at(idx)
        if not pubkey:
            continue
        mint = entry.get("mint")
        if mint:
            token_account_mint[pubkey] = mint
        ui_amount = as_json_dict(entry.get("uiTokenAmount"))
        decimals = ui_amount.get("decimals")
        if decimals is not None:
            token_account_decimals[pubkey] = int(decimals)
        if entry.get("owner") == signer:
            signer_token_accounts.add(pubkey)

    candidates: list[BetAmountResult] = []
    for ix in iter_instructions_in_execution_order(raw_tx):
        program = ix.get("program")
        parsed = as_json_dict(ix.get("parsed"))
        ix_type = parsed.get("type")
        info = as_json_dict(parsed.get("info"))
        source = info.get("source")
        destination = info.get("destination")

        if program == "system" and ix_type == "transfer":
            if destination != signer or source in (None, signer):
                continue
            lamports = info.get("lamports")
            if lamports in (None, ""):
                continue
            try:
                amount = Decimal(int(lamports)) / Decimal(1_000_000_000)
            except (TypeError, ValueError):
                continue
            candidates.append(BetAmountResult(
                display=f"{format_decimal(amount, decimals=9)} SOL",
                raw_delta=amount,
                source="last_inbound_system",
                unit="SOL",
            ))
            continue

        if program == "spl-token" and ix_type in {"transfer", "transferChecked"}:
            if destination not in signer_token_accounts or source in (None, destination):
                continue
            token_amount = as_json_dict(info.get("tokenAmount"))
            mint = info.get("mint") or token_account_mint.get(destination)
            symbol = token_symbol(mint)
            if isinstance(token_amount, dict):
                ui_amount = token_amount.get("uiAmountString")
                if ui_amount not in (None, ""):
                    candidates.append(BetAmountResult(
                        display=f"{ui_amount} {symbol}",
                        raw_delta=Decimal(str(ui_amount)),
                        source="last_inbound_spl",
                        unit=symbol,
                    ))
                    continue
                raw_amount = info.get("amount")
                decimals = token_amount.get("decimals")
                if raw_amount not in (None, "") and decimals is not None:
                    amount = decimal_from_amount(str(raw_amount), int(decimals))
                    candidates.append(BetAmountResult(
                        display=f"{format_decimal(amount, decimals=9)} {symbol}",
                        raw_delta=amount,
                        source="last_inbound_spl",
                        unit=symbol,
                    ))
                    continue
            raw_amount = info.get("amount")
            if raw_amount not in (None, ""):
                decimals = token_account_decimals.get(destination)
                if decimals is not None:
                    amount = decimal_from_amount(str(raw_amount), decimals)
                else:
                    try:
                        amount = Decimal(str(raw_amount))
                    except InvalidOperation:
                        continue
                candidates.append(BetAmountResult(
                    display=f"{format_decimal(amount, decimals=9)} {symbol}",
                    raw_delta=amount,
                    source="last_inbound_spl",
                    unit=symbol,
                ))

    if not candidates:
        return None

    if preferred_unit:
        unit_candidates = [
            c
            for c in candidates
            if c.unit == preferred_unit and c.raw_delta is not None and c.raw_delta > 0
        ]
        if unit_candidates:
            # 过滤明显尘埃入账，避免把末尾找零/极小返还当成主回款。
            threshold = Decimal("0.000001")
            if outbound_amount is not None and outbound_amount > 0:
                dynamic_threshold = outbound_amount * Decimal("0.01")
                if dynamic_threshold > threshold:
                    threshold = dynamic_threshold

            meaningful = [
                c for c in unit_candidates if c.raw_delta is not None and c.raw_delta >= threshold
            ]
            if meaningful:
                return meaningful[-1]

            return max(
                unit_candidates,
                key=lambda c: c.raw_delta if c.raw_delta is not None else Decimal("0"),
            )

    return candidates[-1]


def compute_profit(bet: BetAmountResult, inbound: BetAmountResult | None, success: bool) -> str:
    if not success:
        return "-"
    if not inbound or bet.raw_delta is None or inbound.raw_delta is None:
        return "-"
    if not bet.unit or not inbound.unit or bet.unit != inbound.unit:
        return "-"
    return format_decimal(inbound.raw_delta - bet.raw_delta, decimals=9)


def extract_signature(raw_tx: dict[str, Any]) -> str:
    signatures = raw_tx.get("transaction", {}).get("signatures") or []
    return signatures[0] if signatures else ""


def extract_tip_info(raw_tx: dict[str, Any], provider_by_account: dict[str, str]) -> dict[str, Any]:
    seen: set[tuple[str | None, str, int]] = set()
    hits: list[tuple[str, str, int]] = []

    for ix in iter_all_instructions(raw_tx):
        if ix.get("program") != "system":
            continue
        parsed = as_json_dict(ix.get("parsed"))
        if parsed.get("type") != "transfer":
            continue
        info = as_json_dict(parsed.get("info"))
        source = info.get("source")
        destination = info.get("destination")
        lamports = info.get("lamports")
        if destination not in provider_by_account or lamports is None:
            continue
        try:
            lamports_int = int(lamports)
        except (TypeError, ValueError):
            continue
        dedupe_key = (source, destination, lamports_int)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        hits.append((destination, provider_by_account[destination], lamports_int))

    total_lamports = sum(item[2] for item in hits)
    unique_accounts = [item[0] for item in hits]
    unique_providers = sorted({item[1] for item in hits})

    return {
        "tip_present": bool(hits),
        "tip_accounts": unique_accounts,
        "tip_providers": unique_providers,
        "tip_lamports": total_lamports,
        "tip_sol": Decimal(total_lamports) / Decimal(1_000_000_000),
    }


def extract_priority_fee(raw_tx: dict[str, Any]) -> Decimal:
    meta = raw_tx.get("meta") or {}
    total_fee_lamports = meta.get("fee")
    if total_fee_lamports in (None, ""):
        return Decimal("0")
    try:
        fee_lamports = int(total_fee_lamports)
    except (TypeError, ValueError):
        return Decimal("0")
    # 按用户要求：优先费列展示交易总费用（meta.fee）
    return Decimal(fee_lamports) / Decimal(1_000_000_000)


def build_row(raw_tx: dict[str, Any], token_mint: str, provider_by_account: dict[str, str]) -> dict[str, Any]:
    slot = raw_tx.get("slot")
    rank_in_block = raw_tx.get("tx_index")
    message = raw_tx.get("transaction", {}).get("message", {}) or {}
    signer = parse_signer_wallet(message)
    tip_info = extract_tip_info(raw_tx, provider_by_account)
    bet_amount = compute_bet_amount(raw_tx, token_mint, signer)
    bet_value = "-"
    bet_unit = "-"
    if bet_amount.raw_delta is not None:
        bet_value = format_decimal(bet_amount.raw_delta, decimals=9)
    if bet_amount.unit:
        bet_unit = bet_amount.unit
    inbound_amount = extract_last_inbound_to_signer(
        raw_tx,
        signer,
        preferred_unit=bet_amount.unit,
        outbound_amount=bet_amount.raw_delta,
    )
    priority_fee = extract_priority_fee(raw_tx)
    
    # 从meta.err判断交易是否成功
    meta = raw_tx.get("meta") or {}
    success = meta.get("err") is None
    profit = compute_profit(bet_amount, inbound_amount, success)

    return {
        "slot": slot,
        "rank_in_block": rank_in_block,
        "signature": extract_signature(raw_tx),
        "signer": signer,
        "bet_amount": bet_value,
        "bet_unit": bet_unit,
        "bet_amount_debug": bet_amount.debug_info,
        "profit": profit,
        "priority_fee": format_decimal(priority_fee, decimals=9),
        "tip_present": tip_info["tip_present"],
        "tip_accounts": short_account_list(tip_info["tip_accounts"], max_items=2),
        "tip_amount": format_decimal(tip_info["tip_sol"], decimals=9)
        if tip_info["tip_present"]
        else "-",
        "success": success,
    }


class SolanaRpc:
    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url

    def call(self, method: str, params: list[Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        try:
            response = requests.post(self.rpc_url, json=payload, timeout=RPC_TIMEOUT_SECS)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise SearchError(f"RPC 请求失败：{exc}") from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise SearchError("RPC 返回了无法解析的 JSON 数据。") from exc
        error = data.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise SearchError(f"RPC 返回错误：{message}")
        return data.get("result")

    def get_transaction(self, signature: str, encoding: str = "jsonParsed") -> dict[str, Any]:
        result = self.call(
            "getTransaction",
            [
                signature,
                {
                    "encoding": encoding,
                    "maxSupportedTransactionVersion": 0,
                    "commitment": "confirmed",
                },
            ],
        )
        if not result:
            raise SearchError("没有查到这个交易哈希，请确认签名是否正确。")
        return result

    def get_multiple_accounts(self, addresses: list[str]) -> dict[str, dict[str, Any] | None]:
        account_infos: dict[str, dict[str, Any] | None] = {}
        if not addresses:
            return account_infos

        for start in range(0, len(addresses), MULTIPLE_ACCOUNTS_BATCH_SIZE):
            batch = addresses[start : start + MULTIPLE_ACCOUNTS_BATCH_SIZE]
            result = self.call(
                "getMultipleAccounts",
                [batch, {"encoding": "base64", "commitment": "confirmed"}],
            )
            values = (result or {}).get("value")
            if not isinstance(values, list) or len(values) != len(batch):
                raise SearchError("getMultipleAccounts 返回格式异常。")

            for address, info in zip(batch, values):
                account_infos[address] = info if isinstance(info, dict) else None

        return account_infos

    def get_block(self, slot: int) -> dict[str, Any] | None:
        try:
            return self.call(
                "getBlock",
                [
                    slot,
                    {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0,
                        "transactionDetails": "full",
                        "rewards": False,
                        "commitment": "confirmed",
                    },
                ],
            )
        except SearchError as exc:
            message = str(exc).lower()
            if "skipped" in message or "missing in long-term storage" in message or "not available" in message:
                return None
            raise


class SearchService:
    def __init__(self, rpc_url: str, tip_accounts_path: Path):
        self.rpc = SolanaRpc(rpc_url)
        providers = load_tip_accounts(tip_accounts_path)
        self.provider_by_account: dict[str, str] = {}
        for provider, accounts in providers.items():
            for account in accounts:
                self.provider_by_account[account] = provider

    def _fetch_block_safe(self, slot: int) -> tuple[int, dict[str, Any] | None, str | None]:
        try:
            block = self.rpc.get_block(slot)
            return slot, block, None
        except SearchError as exc:
            return slot, None, str(exc)

    def detect_pools(self, signature: str) -> list[dict[str, str]]:
        if not signature:
            raise SearchError("交易哈希不能为空。")

        raw_tx = self.rpc.get_transaction(signature, encoding="json")
        pools = find_pools(raw_tx, self.rpc.get_multiple_accounts)
        return [
            {
                "dex_name": pool.dex_name,
                "pool_address": pool.pool_address,
                "mint_a": pool.mint_a,
                "mint_b": pool.mint_b,
                "symbol_a": pool.symbol_a,
                "symbol_b": pool.symbol_b,
                "display_name": f"{format_dex_name(pool.dex_name)} ({format_symbol(pool.symbol_a)}-{format_symbol(pool.symbol_b)})",
                "label": (
                    f"{format_dex_name(pool.dex_name)} "
                    f"({format_symbol(pool.symbol_a)}-{format_symbol(pool.symbol_b)}) : "
                    f"{pool.pool_address}"
                ),
            }
            for pool in pools
        ]

    def search(self, signature: str, token_mint: str, window: int) -> dict[str, Any]:
        if not signature:
            raise SearchError("交易哈希不能为空。")
        if not token_mint:
            raise SearchError("账户地址不能为空。")
        if window < 0:
            raise SearchError("上下区块数量不能小于 0。")
        if window > MAX_WINDOW:
            raise SearchError(f"上下区块数量不能大于 {MAX_WINDOW}。")

        base_transaction = self.rpc.get_transaction(signature)
        base_slot = base_transaction.get("slot")
        if base_slot is None:
            raise SearchError("无法从这个交易里解析到区块号。")

        scanned_from = max(0, int(base_slot) - window)
        scanned_to = int(base_slot) + window
        slots = list(range(scanned_from, scanned_to + 1))
        rows: list[dict[str, Any]] = []
        available_blocks = 0
        unavailable_slots = 0
        total_transactions = 0
        block_errors: list[str] = []

        max_workers = min(8, max(1, len(slots)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._fetch_block_safe, slot) for slot in slots]
            for future in concurrent.futures.as_completed(futures):
                slot, block, error = future.result()
                if error:
                    block_errors.append(f"slot {slot}: {error}")
                if not block:
                    unavailable_slots += 1
                    continue
                available_blocks += 1
                block_transactions = block.get("transactions") or []
                total_transactions += len(block_transactions)
                for tx_index, raw_tx in enumerate(block_transactions, start=1):
                    raw_tx["slot"] = slot
                    raw_tx["tx_index"] = tx_index
                    if not transaction_mentions_token(raw_tx, token_mint):
                        continue
                    rows.append(build_row(raw_tx, token_mint, self.provider_by_account))

        if available_blocks == 0:
            if block_errors:
                raise SearchError(f"附近区块全部拉取失败。{block_errors[0]}")
            raise SearchError("附近区块全部不可用，结果无法确认。")

        rows.sort(key=lambda item: (item["slot"], item["signature"]))
        return {
            "summary": {
                "base_slot": base_slot,
                "scanned_from": scanned_from,
                "scanned_to": scanned_to,
                "requested_slots": len(slots),
                "available_blocks": available_blocks,
                "unavailable_slots": unavailable_slots,
                "total_transactions": total_transactions,
                "match_count": len(rows),
            },
            "rows": rows,
        }


class AppHandler(BaseHTTPRequestHandler):
    service: SearchService | None = None

    @staticmethod
    def _normalized_path(raw_path: str) -> str:
        path = urlsplit(raw_path).path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return path

    def do_GET(self) -> None:
        route = self._normalized_path(self.path)
        if route in {"/", "/index.html"}:
            self._send_html(HTML_PAGE)
            return
        self._send_json({"ok": False, "error": "Not Found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        route = self._normalized_path(self.path)
        if route not in {"/api/search", "/api/pools"}:
            self._send_json({"ok": False, "error": "Not Found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            payload = self._read_json()

            if self.service is None:
                raise SearchError("服务尚未初始化。")

            if route == "/api/pools":
                signature = str(payload.get("signature", "")).strip()
                pools = self.service.detect_pools(signature)
                self._send_json({"ok": True, "pools": pools})
                return

            signature = str(payload.get("signature", "")).strip()
            token_mint = str(payload.get("account_address", payload.get("token_mint", ""))).strip()
            window_raw = payload.get("window", 0)
            try:
                window = int(window_raw)
            except (TypeError, ValueError) as exc:
                raise SearchError("上下区块数量必须是整数。") from exc

            result = self.service.search(signature, token_mint, window)
            self._send_json({"ok": True, **result})
        except SearchError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "请求体不是合法 JSON。"}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": f"程序内部错误：{exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _send_html(self, html: str) -> None:
        data = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def kill_port_process(port: int) -> None:
    """杀死占用指定端口的进程"""
    try:
        # 使用lsof查找占用端口的进程
        result = subprocess.run(
            ["lsof", "-i", f":{port}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            # 解析输出，获取PID
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:  # 第一行是标题
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pid = int(parts[1])
                            os.kill(pid, 15)  # SIGTERM
                            print(f"✓ 已停止占用端口 {port} 的进程 (PID: {pid})")
                            import time
                            time.sleep(0.5)  # 等待进程退出
                        except (ValueError, ProcessLookupError, PermissionError):
                            pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # lsof命令不存在或超时，忽略
        pass
    except Exception:
        # 其他错误也忽略，不影响程序启动
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="区块竞争对手查询 GUI")
    parser.add_argument("--host", default=DEFAULT_HOST, help="监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="监听端口，默认 8765")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    
    # 启动前清理占用端口的进程
    kill_port_process(args.port)
    
    env = read_env_file(ENV_PATH)
    rpc_url = build_rpc_url(env)

    AppHandler.service = SearchService(rpc_url=rpc_url, tip_accounts_path=TIP_ACCOUNTS_PATH)
    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    url = f"http://{args.host}:{args.port}"

    print("区块链数据高级查询已启动")
    print(f"本地地址: {url}")
    print(f"RPC 节点: {sanitize_rpc_url(rpc_url)}")
    print("按 Ctrl+C 停止服务")

    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
