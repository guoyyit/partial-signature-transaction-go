# partial-signature-transaction-go

单机本地闭环的多方协作签名服务（包名 `pst`）。一笔交易需要多个各自离线
持有私钥的参与方分别签名，服务负责收集、校验、撤销、合并与最终组装，
不依赖任何外部服务或网络。

## 签名语义

- 签名算法为 Ed25519（`crypto/ed25519`）。每个参与方对**完整交易体**独立
  签名，签名之间没有先后依赖。
- 交易标识 `tx_id = SHA-256(canonical(tx))`。部分签名实际覆盖的消息是带
  域分隔前缀的固定字符串，避免跨消息类型重放：
  - 部分签名：`"PST/PARTIAL/v1/" || tx_id`
  - 撤销签名：`"PST/REVOKE/v1/"  || tx_id`
- 任何持有签名中内嵌公钥的一方都可用 `PartialSignature.Verify(tx)` 独立
  校验；交易体任一字段变化都会改变 `tx_id`，导致所有既有签名失效。
- 撤销必须由同一私钥对 `tx_id` 签名证明，服务不接受无凭据的撤销。
- 同一公钥重复提交**完全相同**的签名视为幂等提交、直接成功；提交同一公钥
  的不同签名会被显式拒绝（`ErrPolicyViolation`），有效签名只保留一份，
  结果与到达顺序无关。

## 规范化与编码版本

部分签名、撤销、完整交易、交易体、元数据、事件均为版本化的紧凑 JSON：

- 字段顺序固定（按 Go 结构体声明顺序），无多余空白，字节切片用标准
  base64，不做 HTML 转义；字节级编码唯一确定。
- 所有结构携带版本字段 `"v"`（交易体为 `"version"`），当前版本为 `1`。
  未知版本一律返回 `ErrUnknownVersion`。
- 解码走严格路径（`strictDecodeJSON`），以下输入全部返回
  `ErrNonCanonical`，绝不静默接受或改写后落盘：
  - 任意多余空白、尾随数据、重复键；
  - 结构体上的未知字段；
  - 重新编码后与输入字节不一致的任何形式。

## 策略配置

```go
type Policy struct {
    Version     int      // 必须为 1
    AllowedKeys [][]byte // 允许签名的 Ed25519 公钥白名单，不可重复
    Threshold   int      // 最终化所需的最少不同公钥签名数（1..len(AllowedKeys)）
}
```

- 只有 `AllowedKeys` 中列出的公钥产生的签名会被接受，其余返回
  `ErrPublicKeyNotAllowed`（拒绝事件仍写入审计日志）。
- 阈值不足时 `Finalize` 返回 `ErrThresholdNotMet`。
- 策略本身会嵌入最终交易，任何一方无需信任服务即可独立验证。

最终交易中的签名按公钥升序排列，因此组装结果与签名到达顺序无关；
`FinalTransaction.Verify()` 会重新校验：策略合法、阈值满足、每个签名都
覆盖内嵌交易体、公钥在白名单内且无重复、排列顺序规范。

## 有效期

- `Register(tx, policy, ttl)` 配置有效期；`ttl <= 0` 表示不过期。
- 过期后新签名、撤销、最终化均返回 `ErrExpired`；已收集签名保留可查。
- 时间来源通过 `Config.Now` 注入，便于测试；默认 `time.Now`。

## 并发与确定性终态

- 每个 `Service` 用单一互斥锁串行化所有状态变更。并发提交不丢签名；
  提交与最终化、撤销与最终化竞争时只有一个确定结果：
    - 撤销先落盘：该签名从活动集合删除，最终交易绝不可能包含它；
    - 最终化先落盘：最终交易不可变，撤销返回 `ErrFinalized`。
- 所有变更（含被拒绝的尝试及原因）按单调序号追加到事件日志，状态完全
  可追溯。

## 持久化与崩溃恢复

存储根目录下每笔交易一个以十六进制 `tx_id` 命名的目录：

```
<dir>/<tx_id_hex>/meta.json    # 交易体、策略、截止时间（原子写）
<dir>/<tx_id_hex>/events.log   # 每行一个 JSON 事件，append + fsync
<dir>/<tx_id_hex>/final.json   # 完整交易（临时文件 + fsync + rename 原子替换）
```

- 内存变更前先 `write + fsync` 事件日志，重启后重放事件恢复活动签名集合，
  可继续收集与撤销。
- 最终化顺序：先原子写 `final.json`（同目录临时文件、`fsync`、`rename`、
  目录 `fsync`），再追加 `finalized` 事件。任何崩溃点都不会留下半写入的
  最终交易：只有完整的 `final.json` 会被恢复。
- 事件日志末尾若出现崩溃造成的半行，打开时会在严格校验下识别并截断到最后
  一条完整记录，之后的追加仍拼接到干净日志上。

## 快速上手

```go
svc, _ := pst.Open(pst.Config{Dir: "./data"})
txID, _ := svc.Register(tx, policy, time.Hour)

sig, _ := pst.SignTransaction(key.Private, tx) // 离线完成
_ = svc.Submit(sig)                            // 任一时刻在线提交

final, err := svc.Finalize(txID)               // 达阈值后组装
received, _ := pst.DecodeFinal(blob)
_ = received.Verify()                          // 任何一方独立验证
```

运行测试：`go test -race ./...`。
