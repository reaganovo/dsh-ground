/**
 * keystone-ground —— 服务器版地基（唯一入口插件）。
 *
 * 契约见 ../CONTRACT.md（先于代码存在）。代码与契约冲突 ⇒ 代码错。
 *
 * 三条不变量，钉在 DSH 原生接缝上：
 *   I1 历史不可改 → dsh-session append-only + replay（原生，不自建）
 *   I2 边界不可越 → ctx.tools.restrict()：能力从 schema 消失
 *   I3 验证不可跳 → ctx.tools.guard()：单调否决，进程内
 *
 * 分层（单向依赖 L6→L5→L4→L3→L2→L1→L0，L1 不许 import 任何带副作用的东西）：
 *   L0 规则数据 · L1 热判决 · L2 结构摘除 · L3 信任域 · L4 授权 · L5 冷自证 · L6 腐烂
 *
 * 本文件只做**装配 + CLI**，不含任何判决逻辑。
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { DEFAULT_RULES, stateDir, stateFile, WHY } from "./L0-rules.js";
import { judge } from "./L1-hot.js";
import { computeFilters, bashWrites } from "./L2-structure.js";
import { checkTrust, seedReadonly, lockCommand } from "./L3-trust.js";
import { loadGrants, grant, revoke } from "./L4-auth.js";
import { health, check, ledger, readEscape, setEscape } from "./L5-cold.js";
import { rotReport } from "./L6-rot.js";

const SELF = fileURLToPath(import.meta.url);

// 对外导出：契约 + 各层能力（测试与外部集成都从这一个入口取）
// 对外 API：只导出外部真会用的（测试 + 集成）。内部实现细节不导出（减少表面积）。
export { DEFAULT_RULES, stateDir, judge, computeFilters, checkTrust, grant, revoke, check, health, rotReport, readEscape, loadGrants };

/* ───────────────────────── 用量台账（C9 数据源，只在 guard 回调里累加）───────────────────────── */
const STATS = new Map();
let sinceFlush = 0;
function bump(rule, isDeny) {
  const r = STATS.get(rule) || { eval: 0, deny: 0 };
  r.eval += isDeny ? 0 : 1;
  if (isDeny) r.deny += 1;
  STATS.set(rule, r);
  if (isDeny || ++sinceFlush >= 200) flushStats();
}
function flushStats() {
  for (const [rule, r] of STATS) ledger({ kind: "stat", rule, eval: r.eval, deny: r.deny });
  STATS.clear();
  sinceFlush = 0;
}

/* ───────────────────────── 装配 ───────────────────────── */
export const name = "keystone-ground";
export const inject = ["tools", "agents"];

export function apply(ctx, config = {}) {
  const rules = { ...loadRules(), ...config };
  fs.mkdirSync(stateDir(), { recursive: true });
  // C14：真源一开始就是"对 agent 只读"。**绝不建 allow.flag**（否则每次装配自动开逃生舱）。
  seedReadonly(stateFile(rules.rulesFile || "rules.json"), JSON.stringify(DEFAULT_RULES, null, 1));
  seedReadonly(stateFile(rules.grantsFile || "grants.jsonl"), "");

  ctx.on("agent/created", ({ agent }) => {
    // COLD 门禁：只要"现在红不红"（微秒级）。**不跑全量契约自证**——那是 --check 的事。
    const st = health(rules);
    // 授权读一次进内存（热路径不读盘）
    const grants = loadGrants();

    // I2 结构层：摘掉不该有的能力（绿态也摘委派类；红态追加摘写类）
    const filters = computeFilters(rules, !st.green);
    try { agent.ctx.tools.restrict(filters); }
    catch (e) { ctx.logger?.warn?.(`${name}: restrict 失败，退化为 guard 兜底：${e}`); }
    ledger({ kind: "restrict", sessionId: agent?.session?.id, deny: filters.deny, red: st.red });

    // I3 单一否决：只有 2 条热判据
    agent.ctx.tools.guard((exec) => {
      let r;
      try { r = judge(rules, { tool: exec.name, args: exec.arguments, grants }); }
      catch { bump("I0", true); return `I0 ${WHY.I0}`; }

      // 红态：write 类已被 restrict 摘掉，bash 写动作在此兜底
      if (!st.green && String(exec.name).toLowerCase() === "bash") {
        const pat = bashWrites(rules, String(exec.arguments?.command || ""));
        if (pat) { bump("I2", true); return `I2 地基红：bash 写动作被拦（${pat}）`; }
      }

      bump(r.rule, r.decision === "deny");
      if (r.decision !== "deny") return undefined;
      ledger({ kind: "deny", tool: exec.name, rule: r.rule, why: r.why });
      return `${r.rule} ${r.why}`;
    });
  });
}

/* ───────────────────────── 规则加载 ───────────────────────── */
export function loadRules() {
  try { return { ...DEFAULT_RULES, ...JSON.parse(fs.readFileSync(S("rules.json"), "utf8")) }; }
  catch { return DEFAULT_RULES; }
}

/* ───────────────────────── CLI ───────────────────────── */
function usage() {
  console.log(`keystone-ground
  --selftest            契约自证（退 0 = 成立）
  --health              门禁：现在红不红（微秒级，会话启动用这个）
  --check               契约自证 + 门禁（退 0 绿 / 1 红）
  --trust               信任域报告（C14）
  --lock                打印锁权属命令（需 sudo）
  --rot                 腐烂报告（只读，不自动删）
  --grants              列授权
  --grant bash:<前缀> <到期> <by>
  --revoke <id> <理由>
  --escape [minutes]    临时放行（须提权创建才生效）
状态目录：${stateDir()}`);
}

function main(argv) {
  const a = argv.slice(2);
  const has = (k) => a.includes(k);
  const arg = (k, def) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : def; };

  if (has("--selftest")) return process.exit(selftest());
  if (has("--check")) {
    const r = check(loadRules(), { force: true, selfTest: selftest });
    console.log(JSON.stringify(r));
    return process.exit(r.green ? 0 : 1);
  }
  if (has("--health")) {
    const r = health(loadRules(), { force: true });
    console.log(JSON.stringify(r));
    return process.exit(r.green ? 0 : 1);
  }
  if (has("--trust")) {
    const t = checkTrust(stateDir(), loadRules());
    console.log(JSON.stringify(t, null, 1));
    return process.exit(t.ok ? 0 : 1);
  }
  if (has("--lock")) {
    const cmd = lockCommand(stateDir(), loadRules());
    console.log(JSON.stringify(cmd ? { needsSudo: true, run: cmd } : { locked: false, why: "真源还没落盘，先跑 --check" }, null, 1));
    return process.exit(cmd ? 0 : 1);
  }
  if (has("--rot")) { flushStats(); console.log(JSON.stringify(rotReport(loadRules()), null, 1)); return process.exit(0); }
  if (has("--grants")) { for (const g of loadGrants()) console.log(JSON.stringify(g)); return process.exit(0); }
  if (has("--grant")) {
    console.log(JSON.stringify(grant({ match: arg("--grant"), expiry: arg("--expiry", "永久"), by: arg("--by", "operator") }), null, 1));
    return process.exit(0);
  }
  if (has("--revoke")) {
    console.log(JSON.stringify(revoke(arg("--revoke"), arg("--reason", "")), null, 1));
    return process.exit(0);
  }
  if (has("--escape")) {
    try { console.log(JSON.stringify(setEscape(arg("--escape", 30)))); return process.exit(0); }
    catch (e) { console.log(JSON.stringify({ error: String(e.message) })); return process.exit(2); }
  }
  usage();
  return process.exit(2);
}

/* ───────────────────────── 自证（每条契约 = 1 正控 + 1 负控）─────────────────────────
 * 压缩原则：契约不放宽，但**判定不重复**。同一不变量用一条正向证明"该放过的放过"、
 * 一条负向证明"该拦的拦住"，就足够双向证伪；多加的断言只是同一件事换个说法（成本×N）。
 */
export function selftest() {
  const R = DEFAULT_RULES;
  let fail = 0;
  const seen = new Set();
  const ck = (cond, msg) => {
    if (!cond) fail = 1;
    console.log((cond ? "  [ ok ] " : "  [FAIL] ") + msg);
    const m = /^(C\d+)/.exec(msg);
    if (m) seen.add(m[1]);
  };
  const SUDO = ["su", "do"].join("");
  const RM = ["r", "m"].join("");
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "kg-"));
  const oldDir = process.env.KEYSTONE_GROUND_DIR;
  process.env.KEYSTONE_GROUND_DIR = TMP;

  try {
    const hotSrc = fs.readFileSync(path.join(path.dirname(SELF), "L1-hot.js"), "utf8");

    // C1 准入：热路径不许含可逆判据（落点/桶），也不许含阻塞调用（C2 合并到同一次源码扫描）
    ck(!/bucket|decidePath|inRoot|placement/.test(hotSrc), "C1 正控：热路径不含可逆判据（落点不进热路径）");
    ck(/DESTRUCTIVE|SECRET_PATTERNS/.test(hotSrc), "C1 负控：热路径确实在判不可逆项（不是空壳）");

    // C2 成本：无阻塞调用 + 单次 ≤10µs
    const banned = ["readFileSync(", "execFileSync(", "execSync(", "spawnSync(", "fetch(", "fs."];
    const hits = banned.filter((b) => hotSrc.includes(b));
    const SAMP = [
      { tool: "bash", args: { command: "ls -la" } },
      { tool: "write", args: { file_path: "/a.md", content: "x" } },
      { tool: "bash", args: { command: SUDO + " " + RM + " -rf /v" + "ar/x" } },
    ];
    for (let i = 0; i < 2000; i++) for (const x of SAMP) judge(R, x);
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 5000; i++) for (const x of SAMP) judge(R, x);
    const us = Number(process.hrtime.bigint() - t0) / 1000 / (5000 * SAMP.length);
    ck(hits.length === 0 && us <= 10, `C2 热路径纯函数 ${us.toFixed(2)}µs ≤10µs、零阻塞调用`);

    // C3 文案：≤40 字节
    ck(Object.values(WHY).every((v) => Buffer.byteLength(v, "utf8") <= 40), `C3 文案 ${Object.keys(WHY).length} 条全 ≤40B`);

    // C4 误拦=0 + 该拦全拦（一条正向覆盖多真实样本，一条负向覆盖多不可逆样本）
    const OK = [
      { tool: "bash", args: { command: "ls -la ~/projects" } },
      { tool: "bash", args: { command: "npm install --save pkg" } },
      { tool: "bash", args: { command: "rm -rf ~/projects/x/_tmp" } },
      { tool: "read", args: { file_path: "/etc/os-release" } },
      { tool: "write", args: { file_path: "/srv/files/20-领域/真源.md", content: "x" } },
      { tool: "web_fetch", args: { url: "https://example.com" } },
    ];
    const BAD = [
      { tool: "bash", args: { command: SUDO + " " + RM + " -rf /v" + "ar/x" } },
      { tool: "bash", args: { command: RM + " -rf /" } },
      { tool: "bash", args: { command: "mkfs.ext4 /dev/sdz" } },
      { tool: "write", args: { file_path: "/a.md", content: "-----BEGIN RSA PRIVATE KEY-----" } },
      { tool: "write", args: { file_path: "/a.md", content: "sk" + "-abcdefghijklmnopqrstuvwx" } },
    ];
    const mis = OK.filter((c) => judge(R, c).decision !== "allow");
    const leak = BAD.filter((c) => judge(R, c).decision !== "deny");
    ck(mis.length === 0, `C4 正控：${OK.length} 个真实样本误拦 0（不误伤）`);
    ck(leak.length === 0, `C4 负控：${BAD.length} 个不可逆样本全拦（不恒绿）`);

    // C5 分层：热判决不看红绿
    ck(judge(R, { tool: "bash", args: { command: "ls" } }).decision === "allow", "C5 热判决与红绿解耦");

    // C6 可自救 + 逃生舱
    const fRed = computeFilters(R, true);
    const EF = path.join(TMP, "allow.flag");
    const otherUid = (process.getuid?.() ?? 1000) === 4242 ? 4243 : 4242;
    fs.writeFileSync(EF, new Date(Date.now() + 600000).toISOString());
    ck(!fRed.deny.includes("read") && readEscape({ file: EF, statFn: () => ({ uid: otherUid }) }).ok,
      "C6 正控：红态不摘 read（可自救）+ 提权创建的 flag 生效");
    ck(!fRed.deny.includes("bash") && !readEscape({ file: EF }).ok,
      "C6 负控：不摘 bash（已知取舍）+ agent 自建 flag 无效");

    // C7 结构优先
    const f = computeFilters(R, false);
    ck(R.blockedTools.every((b) => f.deny.includes(b)) && !hotSrc.includes(`"${R.blockedTools[0]}"`),
      "C7 正控：委派类由结构层摘掉、不在热路径");
    ck(computeFilters({ ...R, blockedTools: [] }, false).deny.length === 0, "C7 负控：名单清空 ⇒ 不摘（不恒绿）");

    // C8 标注：key 全带 type/obsoleted_by，且 type 合法、compensatory 必写 obsoleted_by
    const g = Object.entries(R.gates);
    ck(g.every(([, m]) => m.type && "obsoleted_by" in m && ["structural", "compensatory", "mixed"].includes(m.type)),
      `C8 正控：${g.length} 条判据台账齐备（type + obsoleted_by）`);
    ck(g.every(([, m]) => m.type !== "compensatory" || m.obsoleted_by),
      "C8 负控：补偿型不写 obsoleted_by 即红（防不死规则）");

    // C9 腐烂
    fs.writeFileSync(path.join(TMP, "ledger.jsonl"), [
      { ts: new Date().toISOString(), kind: "stat", rule: "S1", eval: 500, deny: 0 },
      { ts: new Date().toISOString(), kind: "stat", rule: "S2", eval: 500, deny: 12 },
    ].map(JSON.stringify).join("\n") + "\n");
    const by = Object.fromEntries(rotReport(R).rows.map((r) => [r.rule, r]));
    ck(by.S1?.verdict === "腐烂候选", "C9 正控：评估多但零拦截 ⇒ 腐烂候选");
    ck(by.S2?.verdict === "在挣钱", "C9 负控：有拦截 ⇒ 在挣钱（不误删）");

    // C14 信任域
    for (const n of R.trustPaths) seedReadonly(path.join(TMP, n), "{}");
    for (const n of R.trustPaths) fs.chmodSync(path.join(TMP, n), 0o444);
    ck(checkTrust(TMP, R).ok === true, "C14 正控：真源不可写 ⇒ 判绿");
    fs.chmodSync(path.join(TMP, R.trustPaths[0]), 0o644);
    ck(checkTrust(TMP, R).ok === false, "C14 负控：真源可写 ⇒ 判红（守卫可被拆）");

    console.log(`  SELFTEST=${fail ? "RED" : "GREEN"}  (${fail} failed / 契约 ${[...seen].sort().join(",")})`);
    return fail;
  } finally {
    if (oldDir === undefined) delete process.env.KEYSTONE_GROUND_DIR; else process.env.KEYSTONE_GROUND_DIR = oldDir;
    fs.rmSync(TMP, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) main(process.argv);
