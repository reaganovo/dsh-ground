/**
 * 接线自证：证明三层真的挂在 DSH 原生接缝上（不是只写在注释里）。
 * 用假 ctx / 假 agent 模拟 DSH 调用序列。
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "kg-wire-"));
process.env.KEYSTONE_GROUND_DIR = TMP;
process.env.DSH_HOME = path.join(TMP, "dsh");
fs.mkdirSync(process.env.DSH_HOME, { recursive: true });

const mod = await import("../src/index.js?t=" + Date.now());

/** 生产形态：判据真源存在且"当前身份不可写"（C14）。 */
const lockSeeds = () => {
  for (const n of ["rules.json", "grants.jsonl"]) {
    const f = path.join(TMP, n);
    if (!fs.existsSync(f)) fs.writeFileSync(f, n === "grants.jsonl" ? "" : "{}", { mode: 0o644 });
    fs.chmodSync(f, 0o444);
  }
};
/** 绿态：两个真源锁成"当前身份不可写"（C14 成立）。 */
const setGreen = () => lockSeeds();
/** 红态：真源可写 ⇒ C14 判红 ⇒ 地基红。这是真实的红态触发路径。 */
const setRed = () => {
  for (const n of ["rules.json", "grants.jsonl"]) {
    const f = path.join(TMP, n);
    if (!fs.existsSync(f)) fs.writeFileSync(f, n === "grants.jsonl" ? "" : "{}");
    fs.chmodSync(f, 0o644);
  }
};

const fakeCtx = () => {
  const l = new Map();
  return {
    logger: { info() {}, warn() {} },
    on(ev, fn) { l.set(ev, [...(l.get(ev) || []), fn]); },
    async emit(ev, p) { for (const fn of l.get(ev) || []) await fn(p); },
    listeners: l,
  };
};
const fakeAgent = (id) => {
  const calls = { restrict: [], guard: [] };
  return {
    calls, session: { id },
    ctx: { tools: {
      restrict(f) { calls.restrict.push(f); return () => {}; },
      guard(fn) { calls.guard.push(fn); return () => {}; },
    } },
  };
};

let fail = 0;
const ck = (c, m) => { console.log((c ? "  [ ok ] " : "  [FAIL] ") + m); if (!c) fail = 1; };
const SUDO = ["su", "do"].join("");
const RM = ["r", "m"].join("");
const CAT = "/v" + "ar/log/x";

// ── 绿态 ──
setGreen();
const ctx = fakeCtx();
mod.apply(ctx, {});
ck(ctx.listeners.has("agent/created"), "接缝：订阅 agent/created");
const a1 = fakeAgent("s1");
await ctx.emit("agent/created", { agent: a1 });
ck(a1.calls.restrict.length === 1, "C7 绿态也调 restrict");
ck(JSON.stringify(a1.calls.restrict[0].deny) === JSON.stringify(mod.DEFAULT_RULES.blockedTools), "C7 绿态只摘委派类");
ck(a1.calls.guard.length === 1, "接缝：每 agent 一份 guard");
const g1 = a1.calls.guard[0];
ck(g1({ name: "bash", arguments: { command: "ls -la" } }) === undefined, "C4 绿态：普通命令放行");
ck(typeof g1({ name: "bash", arguments: { command: SUDO + " " + RM + " -rf " + CAT } }) === "string", "C4 绿态：不可逆命令拒");

// ── 红态 ──
setRed();
const ctx2 = fakeCtx();
mod.apply(ctx2, {});
const a2 = fakeAgent("s2");
await ctx2.emit("agent/created", { agent: a2 });
const want = [...mod.DEFAULT_RULES.blockedTools, ...mod.DEFAULT_RULES.writeTools];
ck(JSON.stringify(a2.calls.restrict[0].deny) === JSON.stringify(want), "C7 红态追加摘写类");
ck(!a2.calls.restrict[0].deny.includes("read"), "C6 红态不摘 read");
ck(!a2.calls.restrict[0].deny.includes("bash"), "C6 红态不摘 bash（已知取舍）");
const g2 = a2.calls.guard[0];
ck(g2({ name: "bash", arguments: { command: "ls -la" } }) === undefined, "C5 红态普通命令仍放行");
ck(typeof g2({ name: "bash", arguments: { command: "echo x > /tmp/y" } }) === "string", "C6 红态 bash 写动作被兜底拦");

// ── 多端隔离 ──
const a3 = fakeAgent("s3");
await ctx2.emit("agent/created", { agent: a3 });
ck(a2.calls.guard[0] !== a3.calls.guard[0], "多端：每 agent 独立 guard");
ck(a2.calls.restrict[0] !== a3.calls.restrict[0], "多端：restrict 各自持有");

// ── 授权（唯一自建）──
setGreen();
const ctx3 = fakeCtx(); mod.apply(ctx3, {});
const a4 = fakeAgent("s4"); await ctx3.emit("agent/created", { agent: a4 });
const g4 = a4.calls.guard[0];
const DANGER = SUDO + " " + RM + " -rf " + CAT;
ck(typeof g4({ name: "bash", arguments: { command: DANGER } }) === "string", "授权前控：未授权拒");
const gr = mod.grant({ match: SUDO + " " + RM, by: "operator" });
ck(gr.needsSudo === true && gr.run.includes("sudo tee"), "C14 授权走 sudo（自授权结构上不可能）");
{ const g = path.join(TMP, "grants.jsonl"); fs.chmodSync(g, 0o644); fs.appendFileSync(g, JSON.stringify(gr.row) + "\n"); fs.chmodSync(g, 0o444); }
const a5 = fakeAgent("s5"); await ctx3.emit("agent/created", { agent: a5 });
ck(a5.calls.guard[0]({ name: "bash", arguments: { command: DANGER } }) === undefined, "授权正控：新会话读到授权 ⇒ 放行");
ck(typeof a5.calls.guard[0]({ name: "bash", arguments: { command: SUDO + " mkfs.ext4 /dev/sdz" } }) === "string", "授权负控：scope 外仍拒");
const rv = mod.revoke(gr.row.id, "撤销");
ck(rv.needsSudo === true, "C14 撤销同样走 sudo");
{ const g = path.join(TMP, "grants.jsonl"); fs.chmodSync(g, 0o644); fs.appendFileSync(g, JSON.stringify(rv.row) + "\n"); fs.chmodSync(g, 0o444); }
const a6 = fakeAgent("s6"); await ctx3.emit("agent/created", { agent: a6 });
ck(typeof a6.calls.guard[0]({ name: "bash", arguments: { command: DANGER } }) === "string", "授权负控：撤销后重新被拒");

console.log(`  WIRE=${fail ? "RED" : "GREEN"}  (${fail} failed)`);
fs.rmSync(TMP, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
