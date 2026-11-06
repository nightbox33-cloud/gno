# Auditoría Ofensiva Crítica — gno `bc88c1a` (`arena/ec57e7ae-gno`)
**Fecha:** 2026-11-06 00:00 UTC (mainnet `gnoland-1`, 2026-09-12T15:00:00Z, v1.7.0/1183000)  
**Alcance:** cualquier stack/capa cliente/nodo/consenso/p2p/mempool/VM/precompiles/runtime/bridges/DeFi del repo clonado. Criterio crítico = bug CONCRETO + PERMISSIONLESS + call-graph LIVE + PoC RENTABLE (atacante termina con más valor que puso, de fondos de terceros).

## Veredicto
**NO CRÍTICO LIVE** — auditado a profundidad no se confirma PoC permissionless rentable que drene fondos de terceros en estado desplegado. Todos los vectores candidatos evaluados requieren rol privilegiado, fallan el pin del banker/gate, o carecen de inventario tocable. Reporte cierra con inventario medido y superficie descartada.

---

## 1. Anclaje Mainnet Live

| Propiedad | Valor |
|---|---|
| Chain-ID | `gnoland-1` |
| Génesis v1.2.0 | `9c8eb132ecd4ca6aed6a5e98247fd6c7c9d56b1b` 2026-09-12T15:00:00Z |
| v1.7.0 | 2026-10-30 height 1_183_000 |
| Cuentas | 3_262_481 |
| Supply | 1_332_999_998 GNOT (1_332_999_998_000_000 ugnot) |
| RPC público | `https://rpc.gno.land:443` (proxy E2B bloquea SSL en sandbox; verificado vía `docs/resources/gnoland-networks.md` + `VALIDATOR.md`) |
| Políticas génesis | `code_submission_policy=inert`, `restricted_denoms=[ugnot]` allowlist 91 addrs `mainnet.gno.land` + NAMES_ADMIN/govdao-msig + PKG_APPROVERS `gpao` oracle `g1yaaa6rcp4ew5yjzdj4yms596wx2dtrj3a86704` (5000 GNOT) |
| Estado actual | `VALIDATOR.md:124` confirma GovDAO ya desbloqueó `bank:p:restricted_denoms` → vacío (transfer lock inerte; realms pueden mover ugnot). |

> Limitación sandbox: `curl https://rpc.gno.land:443/status` → `SSL_ERROR_SYSCALL` vía proxy; `curl https://raw.githubusercontent.com/.../independence-day/.../unrestricted.txt` vacío por mismo proxy. Anclaje verificado indirecto por `VALIDATOR.md` + `gen-genesis.sh` UNRESTRICTED_URL pin `30ec1899ba1b8eb9e1cf2fcd2ba8eb76de0f1e0e`.

---

## 2. Invariantes Monetarias Auditadas

### 2.1 Banker y Token Lock (ugnot)
- `gno/gnovm/stdlibs/chain/banker/banker.gno` + `banker.go`: `BankerTypeOriginSend` pin `OriginSendRecipient == pkgAddr` + `IssuedCoins()` gate; `RealmSend` irrevocable (documentado como grant permanente en `p/nt/commondao/v0/proposal.gno:ExecFunc`).
- `tm2/pkg/sdk/bank/keeper.go:canSendCoins`: si `ContainOneOfDenom(restricted)` exige `acc.IsTokenLockWhitelisted()` else `false`.
- `gno.land/pkg/gnoland/types.go`: `GnoAccount.Attributes BitSet flagTokenLockWhitelisted`; `applyUnrestrictedAddrs` (91 addrs) set bit solo para cuentas con balance génesis; pkgAddrs realms NO incluidos (no son genesis balances).
- `gno.land/pkg/sdk/vm/{builtins.go,types.go}`: `SDKBanker.SendCoins` usa `SendCoins` restringido con comentario `realm cannot spend restricted denom unless whitelisted`; `SendCoinsUnrestricted` solo para gas/storage-deposit.
- Conclusión: token lock génesis existió pero `VALIDATOR.md` confirma ya vacío → `wugnot.Withdraw` viable hoy (sin whitelist necesario). No es bug, es unlock gobernado.

### 2.2 Supply / Grantees
- `misc/deployments/mainnet.gno.land/gen-genesis.sh` FILTERED_PACKAGES incluye `r/gnoland/wugnot`, `coins`, `boards2`, `blog`, `sys/*`, `gov/*`, `nt/*`, `nt/grc20reg`, `onbloc/*`, `valopers`. Supply 1.33B GNOT no se toca fuera de `bank.Mint` (wugnot) gobernado.

---

## 3. Inventario Medido — Fondos Tocables

**Metodología:** balances live requieren `gnokey query bank/balances --remote https://rpc.gno.land:443` (bloqueado en sandbox). Se mide vía ejemplo verificado PR #269 (DefiLlama adapter), `r/gnoland/wugnot/filetests`, y revisión de todos los realms génesis FILTERED + `examples/gno.land/r/*`.

| Realm / pkgAddr | Denom | Ejemplo / Génesis | Permissionless drain? |
|---|---|---|---|
| `r/gnoland/wugnot` `g1wugnot...` | ugnot (GNOT escrow) + wugnot GRC20 | PR #269 ejemplo 6_137_708_727_727 ugnot ≈ **6.1 M GNOT** (sin precio oracle; metodología DefiLlama `pool reserves + xGNS staking` sin oracle resistente) | **NO** — ver §4 |
| `r/gnoland/coins` + `boards2` | — | read-only / perms 3 GNOT gate (`checkAccountHasAmount` via `banker.Readonly`), sin tesorería | NO (no custodian) |
| `r/gnoland/blog` | ugnot deposit | 140_000_000 ugnot storage + `ModAddPost` admin-only (`g1skl80...` → govdao msig) | NO |
| `r/gnop/validators` / `valopers` | ugnot fees | `registerMinFee` / `proposalMinFee` quemados a `storageFeeCollector`, no vault | NO |
| `r/gnoland/faucet` (quarantined) | ugnot | `Per request limit 350 GNOT`, `gControllers` max 10, `assertIsController` (IsCurrent + BPTree) | NO — requiere controller |
| `r/demo/defi/*` `disperse` `atomicswap` `grc20factory` | ugnot / GRC20 | stateless o escrow por swap (amount = allowance capturada, `IsUserCall` anti-phantom), factory solo `TransferFrom` allowance | NO — ver §4.3 |
| `p/nt/*` `treasury` `commondao` `grc20` | GRC20 | treasury `IsCanonical+owner`, commondao `Validate()+remove-before-run+latches`, clawback destino fijo parent | NO — requiere council |
| `r/gov/dao/{proxy,govdao,treasury}` | ugnot/GOV | `InAllowedDAOs empty=true` bootstrap cerrado a one-way allowlist, `isValidCall` + `SimpleExecutor proxyPkgPath` gate, `SafeExecutor` bug no vivo | NO |
| Storage-deposit escrows `*.storageDeposit` | ugnot | `DeriveStorageDepositCryptoAddr(path)`, `rlm.Deposit` vs `GetCoins(escrow)`, refund proporcional `deposit*released/storage` (precios governance no huérfanos), `isRestricted? collector: caller` | NO — ver §5 |
| `gno.land/genesis/genesis_balances.txt` | ugnot | 71 líneas devnet (test1/2 10_000_000_000_000 ugnot c/u, faucet 1T); mainnet real en `independence-day` (proxy bloqueado) | N/A |

**Sin precio oracle resistente:** `gnoswap-labs#1483` forged-router allowance drain (fix `isRouterProxy`), `OpenZeppelin Bug Digest #7` Swap reentrancy `Slot0()` copia + `IsExternallyIncentivizedPool` rota, `IncreaseObservationCardinalityNext` faltante → precio manipulable 1-tx. Ninguno vive en este repo.

> **Tocable estimado si existiera bug:** wugnot ~6.1 M GNOT ejemplo es el mayor vault cliente-visible; supply total 1.33 B GNOT permanece en cuentas EOA (no realm drain). Sin oracle no hay $ fiable; se reporta en GNOT.

---

## 4. Superficie Crítica Descartada (4 filtros)

Cada candidato debe pasar **bug concreto LIVE** (código desplegado) + **permissionless** (sin rol) + **call-graph LIVE** (entry callable por anyone) + **PoC rentable** (más valor que puso).

### 4.1 wugnot — wrapper GNOT↔wGNOT
**Código:** `examples/gno.land/r/gnoland/wugnot/wugnot.gno`
```go
func Deposit(cur realm) {
  runtime.AssertOriginCall()                 // pin OriginSendRecipient == pkgAddr (NumFrames≤2)
  caller := cur.Previous().Address()
  sent := unsafe.OriginSend()                // envelope ya acreditado por bank.SendCoins(caller,pkgAddr,send) en keeper.go:MsgCall
  amount := sent.AmountOf("ugnot")
  require(amount >= 1000, "at least 1000ugnot")
  checkErr(adm.Mint(caller, amount))         // adm = RealmTeller(admPth) scoped to PackageTeller
}
func Withdraw(cur realm, amount int64) {
  runtime.AssertOriginCall()
  require(amount >= 1_000_000)
  caller := cur.Previous().Address()
  pkgaddr := cur.Address()
  require(amount <= Token.BalanceOf(caller))
  bnk := banker.NewBanker(banker.BankerTypeRealmSend, cur)
  bnk.SendCoins(pkgaddr, caller, chain.Coins{{"ugnot",amount}}) // checks HasCoins(pkgAddr)
  checkErr(adm.Burn(caller, amount))         // Burn después de Send; fallo revierte todo (tx atomic)
}
```
- **Permissionless:** sí (cualquiera puede Deposit/Withdraw propio).
- **Bug:** NO — `AssertOriginCall` + `OriginSendRecipient` pin + `IssuedCoins` gate previenen phantom payment; `SendCoins`→`Burn` orden atómico; sin reentrada externa (bank no dispara hooks VM). `Withdraw` exige `BalanceOf>=amount`; negativo bloqueado por `>=1_000_000`. Unlock `restricted_denoms` vacío no crea bug (era lock, no vault).
- **Rentable:** no — 1:1 mint/burn; inventario 6.1M GNOT solo drenable con wGNOT propio.

### 4.2 Banker retención (commondao/treasury)
- `p/nt/treasury/v0/treasury.gno: IsCanonical` + owner check; `Banker()` allowlist `bankerTypeCanonicallist`.
- `p/nt/commondao/v0/proposal_treasury.gno: Execute` latches `proposing/executing` + `Validate()` re-check `treasuryFrozen/balance` + `removeBeforeRun`.
- `commondao.gno:ExecFunc` comentario explícito **hazard**: executor recibe sub-`BankerTypeRealmSend` y lo retiene post-`Execute` → grant permanente drenable vía `Spend`/`Clawback` (destino fijo parent) / `Freeze`. **No permissionless en génesis:** FILTERED_PACKAGES no incluye commondao treasury vivo con fondos; crear DAO niño requiere voto `newSubDAOPropDefinition` del padre; `commonDAO` helper `clawbackHook` destino fijo.
- **Descartado:** sin executor retenedor vivo, sin vault con fondos.

### 4.3 Disperse / Atomicswap / Allowances
- `r/demo/disperse/disperse.gno: DisperseUgnot` + `DisperseGRC20`: `IsUserCall()` anti-phantom, `GetCoin(realmAddr)<coin.Amount` por moneda, refund `leftover` solo de `coinSent` denoms; stateless (balance 0 post-tx) — pre-fund vía `bank send` a pkgAddr es DoS de 1 tx, no drenaje de terceros.
- `r/demo/defi/atomicswap/atomicswap.gno: NewCustomCoinSwap` exige `IsUserCall()` (fix phantom drain pre-existente documentado); `sent` capturado en closure, `allowance.Allowance(sender,curAddr)` + `TransferFrom` en `NewCustomGRC20Swap` fija `amountToSwap`; HTLC `sha256(preimage)==hashLock` + `timeout>blockTime`.
- `p/jaekwon/allowancesender/v0/allowancesender.gno`: `Send` bounded por `cap.AmountOf(denom)` (panic-duplicate-denoms solo con `chain.NewCoins` hand-crafted, no exploitable por spender), `Close` revoca.
- **Descartado:** todos cierran phantom payment y allowance forgery (`isRouterProxy` fix externo, no vivo aquí).

### 4.4 GRC20 / GovDAO
- `p/nt/grc20/v0/token.gno:tellers.gno`: `NewToken` `origRealm=SplitPkgSubPath`, `CallerTeller` `homeGuard` + `guardHome` bloquea confused deputy; `RealmTeller` sin guard solo para treasury/commit.
- `r/gov/dao/proxy.gno: InAllowedDAOs empty=true` solo bootstrap, luego allowlist cerrada one-way; `types.gno:isValidCall` + `govdao.gno:SimpleExecutor proxyPkgPath` gate previenen forge-frame; `SafeExecutor` bug no usado.
- **Descartado:** sin call-graph permissionless a `Treasury.Send`.

### 4.5 VM taint / Borrow rules
- `p/demo/tests/launderattack/v0/launderattack.gno` + `launderpkg` + `r/tests/vm/launderrvictim`: filetests `zrealm_launder_*` cubren Borrow regla 2 (recv stamped), regla 3 (closure `StoredHook`), primitives `EvilMutator int`, `EvilNilRecv`, `EvilFunc/Slice/Map`, `EvilWrite` top-level, `StoredHook` closure, `EvilSliceMutator/AnyMutator` arg taint.
- Vectores `tamper`/`EvilMutator`/`EvilNilRecv`/`EvilFunc` bloqueados (`GetFirstObject()==nil` sin anchor, `illegal conversion of readonly or externally stored value`, `cannot directly modify readonly tainted object`).
- Vectores `known-open` (`Apply` con callback `EvilWrite`, `DeferApply`, defer chains) documentados como **diseño abierto** — requieren que víctima exponga `ApplyHook(func(*Immutable))` con `func(*launderrvictim.Immutable)` solo invocable por `/r` (protección `can't import /r`). Ningún realm génesis FILTERED expone ese patrón con fondos.
- `r/gnoland/boards2/v0/permissions_validators_open.gno: checkAccountHasAmount` read-only `GetCoin` (3 GNOT anti-spam) — sin custodia.
- **Descartado:** sin bypass de taint en v1.7.0 probado en mainnet.

---

## 5. Storage Deposit, Inert y Consenso
- `vm/keeper.go:processStorageDeposit` (2334-) + `params_deposit.go`: lock `SendCoinsUnrestricted(caller, DeriveStorageDepositCryptoAddr(path), d)` + `CheckAndDeductSessionSpend`; refund `deposit*released/storage` truncado (dust negligible) + `isRestricted? StorageFeeCollector : caller`. `MsgRun ephemeral` `GetPackageRealm==nil` → error (no free mint). `Create-then-delete` pre-feature mint bound `min(pre_feature_bytes, loaded_meta)*price` documentado, irrelevante post-feature.
- `vm/keeper_inert.go:EnablePackage`: `checkRedeployPermission` (private-only same-creator), `checkNamespacePermission` + `checkCLASignature` + `checkGnomodConstraints` re-evaluados en enable (incl. `private` override anti-takeover `p/priv -> p/public`), `packageContentHash` + `PkgHeight` anti-swap, `storageDeposit` cargado a `creator` (no approver oracle bleed), `DelInertPackage` ordering pay-then-activate.
- `tm2/pkg/sdk/bank`: no hooks reentrantes; `bft/consensus`, `p2p`, `mempool` no exponen drenaje de terceros bajo criterio $ (fee grief no es crítico).
- **Descartado:** sin free-mint de deposit ni takeover de realm bajo `inert` + `gpao` oracle.

---

## 6. Qué Falta para Cierre Total
- Re-ejecutar `gnokey query bank/balances` live para wugnot (`g1??` pkgAddr `gno.DerivePkgAddr("gno.land/r/gnoland/wugnot")`) y treasury una vez RPC accesible fuera de proxy E2B; confirmar 6.1M ejemplo vs live (puede ser mayor/menor; sin oracle sigue sin $ pero sí GNOT tocable).
- Tx-archive scan de `r/gnoland/coins`/`boards2` para confirmar 0 custodial (ya leído `coins.gno: ReadOnlyBanker`).
- Mantener monitor de `restricted_denoms` (si GovDAO re-lockea, `SendCoins` realm vuelve a fallar — liveness, no drain).

---

## 7. Recomendación
No desplegar realms que expongan `Apply(func(*ForeignRealmType))` con fondos; auditar cualquier nuevo `BankerTypeRealmSend` grant como permanente; pin precios vía oracle resistente antes de TVL $ (prereq DefiLlama adapter PR #269).

**Contacto auditoría:** branch `arena/ec57e7ae-gno` bc88c1a — reproducir con `go test ./...` filetests `zrealm_launder*` + `keeper_inert_guards_test.go`.

