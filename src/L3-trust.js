/**
 * L3-trust —— 信任域（契约 C14）：判据真源不许在判据执行体的可写域里。
 *
 * 这是本插件**唯一无法用"拒绝命令"解决**的问题，所以用文件系统权属解决：
 *   判据真源 root 拥有 + 0644 ⇒ agent（lg）因 other 无写位而改不了 ⇒ 结构上不可能拆守卫。
 *
 * 为什么不用黑名单：黑名单要枚举命令，每加一个新 CLI 就得记得补，漏一个就破防 —— 会腐烂。
 *
 * 依赖：L0。
 */
import fs from "node:fs";
import path from "node:path";
import { stateDir } from "./L0-rules.js";

function statOf(name, dir) {
  const f = path.join(dir, name);
  try {
    const st = fs.statSync(f);
    return { name, exists: true, uid: st.uid, gid: st.gid, mode: st.mode.toString(8).slice(-3) };
  } catch {
    return { name, exists: false };
  }
}

/**
 * 判据 = **当前进程身份能不能写**（不是"别人能不能写"）。
 *   root 拥有 + 0644 ⇒ 部署机跑时 other 无写位 ⇒ 改不了，操作者 sudo 后能改 ✓
 *   lg 拥有 + 0644 ⇒ self 有写位 ⇒ 改得了 ✗（守卫可被自己拆）
 */
export function checkTrust(dir = stateDir(), rules) {
  const myUid = process.getuid?.() ?? -1;
  const myGid = process.getgid?.() ?? -1;
  const paths = rules?.trustPaths || ["rules.json", "grants.jsonl"];
  const rows = [];
  for (const n of paths) {
    const r = statOf(n, dir);
    if (!r.exists) { rows.push({ ...r, ok: false, why: "缺失（守卫可随手创建）" }); continue; }
    const canWrite =
      r.uid === myUid ? /[2367]/.test(r.mode[0])
      : r.gid === myGid ? /[2367]/.test(r.mode[1])
      : /[2367]/.test(r.mode[2]);
    rows.push({ ...r, ok: !canWrite, why: canWrite ? "当前身份可写 ⇒ 守卫可被自己拆" : "" });
  }
  return { ok: rows.every((r) => r.ok), rows, bad: rows.filter((r) => !r.ok), uid: myUid };
}

/** 落盘：以 0644 建（幂等）。已存在不动。 */
export function seedReadonly(f, content) {
  try {
    if (!fs.existsSync(f)) {
      fs.writeFileSync(f, content, { mode: 0o644 });
      try { fs.chmodSync(f, 0o644); } catch { /* 已最严 */ }
    }
  } catch { /* 只读挂载不崩 */ }
}

/** 产出锁权属命令（不执行）。agent 解不开 ⇒ 不腐烂。 */
export function lockCommand(dir = stateDir(), rules) {
  const cmds = [];
  for (const n of rules?.trustPaths || ["rules.json", "grants.jsonl"]) {
    const f = path.join(dir, n);
    if (fs.existsSync(f)) cmds.push(`chown root:root "${f}" && chmod 644 "${f}"`);
  }
  const lf = path.join(dir, rules?.ledgerFile || "ledger.jsonl");
  // 账本归"当前用户"（不硬编码 lg：服务器上是 keystone）
  if (fs.existsSync(lf)) {
    const u = process.env.USER || process.env.LOGNAME || "root";
    cmds.push(`chown ${u}:${u} "${lf}" && chmod 644 "${lf}"`);
  }
  return cmds.length ? `sudo bash -c '${cmds.join(" && ")}'` : null;
}
