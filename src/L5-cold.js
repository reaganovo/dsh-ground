/**
 * L5-cold —— 冷路径：自证 + 逃生舱 + 留证（会话开始一次）。
 *
 * 为什么单列一层：它要 spawn 子进程（60ms 量级），绝不能进热路径。
 * 契约 C5：红/绿只在这里算一次，热路径拿结果（HOT 与 COLD 物理解耦）。
 *
 * 依赖：L0、L3。
 */
import fs from "node:fs";
import path from "node:path";
import { stateDir, stateFile } from "./L0-rules.js";
import { checkTrust } from "./L3-trust.js";

let cache = { at: 0, key: "", result: null };

/**
 * 缓存键 = 规则内容 + **信任域状态**。
 * 为什么必须含信任域：C14 的成败取决于文件权限，而权限可以在会话中途被改。
 * 只按规则内容做键 ⇒ 权限变了缓存还认为绿 ⇒ 假绿（2026-10-20 被 wire 测试抓到）。
 */
function cacheKey(rules) {
  const trust = checkTrust(stateDir(), rules).rows.map((r) => `${r.name}:${r.mode}:${r.uid}`).join(",");
  const s = JSON.stringify({ b: rules.blockedTools, w: rules.writeTools }) + "|" + trust;
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h + ":" + s.length;
}

/**
 * 逃生舱判定（纯函数，可注入 stat 供自证）。
 * 三条同时成立：① 内容写死未来时刻（不看 mtime）② 提权身份创建 ③ 未过期。
 *   不看 mtime：mtime 会被 touch/复制刷新 ⇒ 等于永久后门。
 *   必须提权：否则 agent 自己写个 flag 就自开天窗。
 */
export function readEscape({ file, now = Date.now(), myUid = process.getuid?.() ?? -1, statFn } = {}) {
  const f = file || stateFile("allow.flag");
  try {
    const st = statFn ? statFn(f) : fs.statSync(f);
    const raw = fs.readFileSync(f, "utf8").trim();
    const exp = raw ? Date.parse(raw) : NaN;
    // 判据：flag 属主 ≠ 当前进程身份（不是"属主是 root"）。
    // 为什么：跑 selftest 时进程可能是 root，若写死 "uid===0 就算提权"，
    // 则 root 下所有 flag 都算数 ⇒ 判据在 root 环境假绿/假红。
    const byPrivileged = st.uid !== myUid;
    if (Number.isFinite(exp) && exp > now && byPrivileged) return { ok: true, exp, byPrivileged };
    return { ok: false, exp, byPrivileged,
      why: !Number.isFinite(exp) ? "无有效时刻" : exp <= now ? "已过期" : "非提权创建" };
  } catch { return { ok: false, why: "无逃生舱" }; }
}

/** 留证：账本追加（失败不改判据；DSH 会话日志另有记录）。 */
export function ledger(row) {
  try {
    const f = stateFile("ledger.jsonl");
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.appendFileSync(f, JSON.stringify({ ts: new Date().toISOString(), ...row }) + "\n");
  } catch { /* 留证失败静默，绝不改判据 */ }
}

/**
 * COLD 自证：跑 C14 信任域 + 注入的自证函数。TTL 60s，规则哈希作缓存键（改规则自动失效）。
 *
 * 为什么**不 spawn 子进程**（2026-10-20 结构性重构）：
 *   旧设计把自证写成 rules.json 里的命令字符串 ["SELF","--selftest"]，由执行器替换占位符。
 *   这是隐式契约 —— 错了只会在运行时以 spawn-fail 暴露，只能靠"事后加判据抓 spawn-fail"
 *   补漏（典型的自下而上）。自证本来就是进程内函数调用，spawn 只换来 60ms + 路径解析 + 占位符。
 *   ⇒ 自证 = 代码，不是数据。rules.json 只放**策略**（名单/阈值/正则/文案），不放**机制**。
 *
 * @param {object} rules
 * @param {object} opts { force, selfTest }  selfTest = 自证函数（由 index 注入，保持单向依赖）
 * @returns {{green:boolean, red:string[], escaped?:boolean}}
 */
export function health(rules, { force = false } = {}) {
  const now = Date.now();
  const key = cacheKey(rules);
  if (!force && cache.result && cache.key === key && now - cache.at < 60000) return cache.result;

  const esc = readEscape();
  if (esc.ok) {
    const r = { green: true, red: [], escaped: true, expiresAt: new Date(esc.exp).toISOString() };
    cache = { at: now, key, result: r };
    return r;
  }
  const red = [];
  const trust = checkTrust(stateDir(), rules);
  if (!trust.ok) red.push(`C14 信任域未锁：${trust.bad.map((b) => b.name).join(",")} 可被当前身份改写`);
  const r = { green: red.length === 0, red, escaped: false };
  cache = { at: now, key, result: r };
  ledger({ kind: "health", green: r.green, red: r.red });
  return r;
}

/**
 * 契约自证（--check / --selftest 用，**会话启动不走这里**）。
 * 与 health() 分开的理由：诊断"我有没有病"和门禁"能不能干活"是两件事。
 *   会话启动只要 health()（判据级，微秒），不要 14ms 的全量自证 + 29 行输出。
 */
export function check(rules, { force = false, selfTest } = {}) {
  const now = Date.now();
  const key = cacheKey(rules);
  if (!force && cache.result && cache.key === key && now - cache.at < 60000) return cache.result;

  const base = health(rules, { force: true });
  const red = [...base.red];

  // 自证：进程内调用（不 spawn）。抛异常 = 红，与"子进程退非 0"语义一致。
  if (typeof selfTest === "function") {
    try {
      const n = selfTest();
      if (n !== 0) red.push(`C0 自证 ${n} 条未通过`);
    } catch (e) {
      red.push(`C0 自证抛异常：${String(e && e.message || e).slice(0, 80)}`);
    }
  }
  const r = { green: red.length === 0, red, escaped: false };
  cache = { at: now, key, result: r };
  ledger({ kind: "check", green: r.green, red: r.red });
  return r;
}

/** 写逃生舱：内容 = 绝对过期时刻。必须由提权身份调用才生效。 */
export function setEscape(minutes) {
  const m = Number(minutes);
  if (!Number.isFinite(m) || m <= 0 || m > 1440) throw new Error("minutes 必须在 1..1440");
  const f = stateFile("allow.flag");
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const exp = new Date(Date.now() + m * 60000);
  fs.writeFileSync(f, exp.toISOString());
  return { escapedForMinutes: m, expiresAt: exp.toISOString() };
}
