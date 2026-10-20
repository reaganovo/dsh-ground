/**
 * L4-auth —— 授权持久化（**DSH 唯一确认的空位**）。
 *
 * 证据（dsh-user-approval/README.md:155）：
 *   "Only one-shot grants exist — no allow-always, remembered rule,
 *    revocation, or grant store; session policy is only ask / never."
 *
 * 设计（C14 正推）：授权文件对 agent 只读 ⇒ 自授权结构上不可能；
 *   而操作者要随时能授权 ⇒ 授权动作走 sudo，与改规则同一条提权路径。
 *
 * 依赖：L0 与 L3（seedReadonly）。
 */
import fs from "node:fs";
import path from "node:path";
import { stateDir } from "./L0-rules.js";

const file = () => path.join(stateDir(), "grants.jsonl");

/** 读授权：撤销的排除，过期的排除。 */
export function loadGrants() {
  try {
    const rows = fs.readFileSync(file(), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const revoked = new Set(rows.filter((g) => g.kind === "revoke").map((g) => g.target));
    return rows.filter((g) => {
      if (g.kind === "revoke" || revoked.has(g.id)) return false;
      if (!g.expiry || g.expiry === "永久") return true;
      const d = new Date(g.expiry);
      return Number.isNaN(d.getTime()) || d.getTime() >= Date.now();
    });
  } catch { return []; }
}

/** 授权：产出提权命令，不直接写（与 --lock 同一条路径）。 */
export function grant({ kind = "bash", match, expiry = "永久", by }) {
  if (!match || !by) throw new Error("grant 需要 match / by");
  if (kind !== "bash") throw new Error("kind 只支持 bash（路径类可逆，不进热路径）");
  const row = { id: `${kind}:${match}:${Date.now()}`, kind, match, expiry, by };
  return { needsSudo: true, row, run: `printf '%s\\n' '${JSON.stringify(row)}' | sudo tee -a "${file()}"` };
}

/** 撤销：同一条提权路径。 */
export function revoke(id, reason = "") {
  const row = { kind: "revoke", target: id, reason, by: "user" };
  return { needsSudo: true, row, run: `printf '%s\\n' '${JSON.stringify(row)}' | sudo tee -a "${file()}"` };
}
