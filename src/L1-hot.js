/**
 * L1-hot —— 热路径判决（每次工具调用，必须纯函数）。
 *
 * 契约 C2：本文件**不许** import fs / child_process / 网络。
 *   实测预算 10µs，当前 0.30µs。
 * 契约 C1：只有「不可逆」的判据在这里。可逆的（落点放错）不进热路径。
 *
 * 依赖：只 import L0（数据）。不许 import 任何上层。
 */
import { SECRET_PATTERNS, DESTRUCTIVE, WHY } from "./L0-rules.js";

/**
 * 一次工具调用 → { decision: allow|deny, rule, why }。
 * @param {object} rules   L0 规则表（含 writeTools）
 * @param {object} call    { tool, args, grants }
 */
export function judge(rules, { tool, args, grants = [] } = {}) {
  const t = String(tool || "").toLowerCase();
  const a = args && typeof args === "object" ? args : {};

  if (t === "bash") {
    const cmd = String(a.command || "");
    if (!cmd) return { decision: "allow", rule: "R-none" };

    for (const [rx, code] of DESTRUCTIVE) {
      if (!rx.test(cmd)) continue;
      // 授权放行：命中已授权 scope（授权存内存，热路径不读盘）
      for (const g of grants) {
        if (g.kind === "bash" && cmd.startsWith(g.match)) return { decision: "allow", rule: "G" };
      }
      return { decision: "deny", rule: code, why: WHY[code] };
    }
    return { decision: "allow", rule: "R-none" };
  }

  // 凭据明文只可能在写类工具的参数里
  if (rules.writeTools.includes(t)) {
    const blob = JSON.stringify(a);
    for (const [rx, code] of SECRET_PATTERNS) {
      if (rx.test(blob)) return { decision: "deny", rule: code, why: WHY[code] };
    }
  }
  return { decision: "allow", rule: "R-none" };
}
