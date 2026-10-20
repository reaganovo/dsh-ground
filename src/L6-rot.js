/**
 * L6-rot —— 腐烂报告（契约 C8/C9）。
 *
 * 为什么必须有：判据会腐烂。两条实证——
 *   · Boris Cherny：每代新模型删掉 80% 系统提示（旧规则在纠模型已会的毛病）
 *   · §2609.24972：无删除规则的进化循环"beyond a point of dimishing returns"，
 *     被反复调用但零收益的组件越积越多
 *
 * 形态抄 spec-kit 的 converge：**只读，只出报告，不自动删**。
 *   自动删判据 = 让一个循环改自己的安全边界（"脚本杀自己"那一类病）。
 *
 * 依赖：L0、L5（ledger 读取）。
 */
import fs from "node:fs";
import path from "node:path";
import { stateDir, stateFile, DEFAULT_RULES } from "./L0-rules.js";

/** 读账本 → 按 rule 汇总窗口内的 eval/deny。 */
export function rotReport(rules = DEFAULT_RULES) {
  const now = Date.now();
  const windowMs = (rules.rot?.windowDays || 30) * 86400000;
  const minEvals = rules.rot?.minEvals || 200;
  const agg = new Map();
  try {
    const f = path.join(stateDir(), rules.ledgerFile || "ledger.jsonl");
    for (const line of fs.readFileSync(f, "utf8").split("\n").filter(Boolean)) {
      let row;
      try { row = JSON.parse(line); } catch { continue; }
      if (row.kind !== "stat") continue;
      const t = Date.parse(row.ts || "");
      if (Number.isFinite(t) && now - t > windowMs) continue;
      const a = agg.get(row.rule) || { eval: 0, deny: 0 };
      a.eval += row.eval || 0;
      a.deny += row.deny || 0;
      agg.set(row.rule, a);
    }
  } catch { /* 无账本 = 还没跑过 */ }

  const meta = rules.gates || {};
  const rows = [...agg.entries()].map(([rule, a]) => ({
    rule, eval: a.eval, deny: a.deny,
    type: meta[rule]?.type || "未标注",
    obsoleted_by: meta[rule]?.obsoleted_by ?? null,
    verdict: a.eval >= minEvals && a.deny === 0 ? "腐烂候选" : (a.deny > 0 ? "在挣钱" : "样本不足"),
  }));
  return {
    generatedAt: new Date().toISOString(),
    windowDays: rules.rot?.windowDays || 30,
    minEvals, rows,
    unknown: [...agg.keys()].filter((r) => !meta[r]),
  };
}
