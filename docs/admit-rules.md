# otpburn admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{account}|{counter}|{code}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- 在 ±window 步长内匹配 code；超出 window_exceeded
- 同一 counter 已在 burn-store 则 replay；仅成功校验写入
- kid 必须在 epoch [not_before,not_after]；revoked 仍拒
- account 必须在 allow_accounts

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Fixture expectations

Allow cases: ok-now, ok-drift

Deny cases: bad-code, window, replay, revoked, epoch, account, skew-step, empty

Reason codes should be stable snake_case identifiers matching the failing gate.
