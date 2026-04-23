#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable

import requests

try:
    from solders.pubkey import Pubkey as SoldersPubkey
except ImportError:
    SoldersPubkey = None


RPC_URL = "https://mainnet.helius-rpc.com/?api-key=899d8ca2-8066-46a0-830c-c9dc71685fba"
RPC_TIMEOUT_SECS = 45
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


def rpc_call(method: str, params: list[Any]) -> Any:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }

    try:
        response = requests.post(RPC_URL, json=payload, timeout=RPC_TIMEOUT_SECS)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"RPC 请求失败: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("RPC 返回了不可解析的 JSON。") from exc

    if data.get("error"):
        error = data["error"]
        message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
        raise RuntimeError(f"RPC 返回错误: {message}")

    return data.get("result")


def get_transaction(signature: str) -> dict[str, Any]:
    result = rpc_call(
        "getTransaction",
        [
            signature,
            {
                "encoding": "json",
                "commitment": "confirmed",
                "maxSupportedTransactionVersion": 0,
            },
        ],
    )

    if not result:
        raise RuntimeError("没有查到这笔交易，请确认哈希是否正确。")
    return result


def get_multiple_accounts(addresses: list[str]) -> dict[str, dict[str, Any] | None]:
    account_infos: dict[str, dict[str, Any] | None] = {}

    for start in range(0, len(addresses), MULTIPLE_ACCOUNTS_BATCH_SIZE):
        batch = addresses[start : start + MULTIPLE_ACCOUNTS_BATCH_SIZE]
        result = rpc_call(
            "getMultipleAccounts",
            [batch, {"encoding": "base64", "commitment": "confirmed"}],
        )
        values = (result or {}).get("value")
        if not isinstance(values, list) or len(values) != len(batch):
            raise RuntimeError("getMultipleAccounts 返回格式异常。")

        for address, info in zip(batch, values):
            account_infos[address] = info if isinstance(info, dict) else None

    return account_infos


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


# 非 DEX_PROGRAMS 里的「池子 DEX」程序，但会在 CPI 里反复出现（系统、SPL、聚合路由等）。
# 仅用于「是否还存在其它非内置程序」的过滤；支持的池子 DEX 仍以 DEX_PROGRAMS 为准。
SOLANA_CHAIN_BUILTIN_PROGRAM_IDS: frozenset[str] = frozenset(
    {
        "11111111111111111111111111111111",
        "ComputeBudget111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ATokenGPvbdGWxt5Kt9oEcJYd8duyVoENDEMWT2jAnt",
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
        "memoisgqLwKmqjVjZWXLZwW4FnJs66jVBKD5TJCSsb",
        "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
        "SysvarRent111111111111111111111111111111111",
        "SysvarC1ock1111111111111111111111111111111",
        "Sysvar1nstructions1111111111111111111111111",
        "SysvarRecentB1ockHashes111111111111111111111",
        "SysvarSlotHashes111111111111111111111111111",
        "SysvarSlotHistory11111111111111111111111111",
        "SysvarSt1akeHistory1111111111111111111111111",
        "SysvarEpochSchedu1e111111111111111111111111",
        "Vote111111111111111111111111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "Config1111111111111111111111111111111111",
        "KeccakSecp256k1111111111111111111111111111111",
        "Ed25519SigVerify111111111111111111111111111",
        "Secp256k1SigVerify111111111111111111111111111",
        "AddressLookupTab1e1111111111111111111111111",
        "BPFLoaderUpgradeab1e1111111111111111111111111111111111",
        "NativeLoader1111111111111111111111111111111",
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
        "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB",
        "JUP5cHjnnCx2DmkVj99Kwd7Sdfk1CFEr9mNMSVn4v7W",
    }
)


def list_invoked_program_ids_outside_supported_dex(
    raw_tx: dict[str, Any],
    extra_allow_program_ids: frozenset[str] | None = None,
) -> list[str]:
    """
    本交易中出现过的 instruction program_id 里，既不在 DEX_PROGRAMS（8 个池子 DEX），
    也不在 SOLANA_CHAIN_BUILTIN_PROGRAM_IDS 与 extra_allow 中的程序（去重后排序列表）。
    用于监听脚本：若非空则视为「含非支持 DEX 相关 CPI」。
    """
    supported = frozenset(DEX_PROGRAMS.keys())
    allowed = SOLANA_CHAIN_BUILTIN_PROGRAM_IDS | (extra_allow_program_ids or frozenset())
    seen: set[str] = set()
    out: list[str] = []
    for ins in iter_resolved_instructions(raw_tx):
        pid = ins.program_id
        if pid in supported or pid in allowed:
            continue
        if pid not in seen:
            seen.add(pid)
            out.append(pid)
    out.sort()
    return out


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


def resolve_symbols(mints: list[str]) -> dict[str, str]:
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

    lookup_infos = get_multiple_accounts(lookup_targets)

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

    pointer_infos = get_multiple_accounts(list(pointer_targets))
    for pointer_target, related_mints in pointer_targets.items():
        account_info = pointer_infos.get(pointer_target)
        metaplex_symbol = decode_metadata_symbol(account_info)
        for mint in related_mints:
            symbol = metaplex_symbol or decode_token_metadata_account_symbol(account_info, mint)
            if symbol:
                symbols[mint] = symbol
                break

    return symbols


def find_pools(raw_tx: dict[str, Any]) -> list[PoolInfo]:
    candidate_accounts: list[str] = []
    seen_accounts: set[str] = set()

    for instruction in iter_resolved_instructions(raw_tx):
        for account in instruction.accounts:
            if account in seen_accounts:
                continue
            seen_accounts.add(account)
            candidate_accounts.append(account)

    account_infos = get_multiple_accounts(candidate_accounts)

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

    symbol_by_mint = resolve_symbols([pool.mint_a for pool in pools] + [pool.mint_b for pool in pools])
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


def main() -> int:
    while True:
        try:
            signature = input("\n请输入交易哈希 (或按 Ctrl+C 退出): ").strip()
            if not signature:
                print("哈希不能为空，请重试")
                continue

            raw_tx = get_transaction(signature)
            pools = find_pools(raw_tx)
        except KeyboardInterrupt:
            print("\n再见！")
            return 0
        except RuntimeError as exc:
            print(f"错误: {exc}", file=sys.stderr)
            continue

        if not pools:
            print("未识别到池子")
        else:
            for pool in pools:
                print(
                    f"{format_dex_name(pool.dex_name)} "
                    f"({format_symbol(pool.symbol_a)}-{format_symbol(pool.symbol_b)}) : "
                    f"{pool.pool_address}"
                )


if __name__ == "__main__":
    raise SystemExit(main())
