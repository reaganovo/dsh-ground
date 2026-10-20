/**
 * L2-structure —— 结构层：决定从 schema 里**摘掉**哪些工具。
 *
 * 契约 C7：能靠结构解决的不写成运行时判据。
 *   摘掉 = 模型看不见 = 没有"要不要拒绝"这个问题 = 零 token、零往返。
 * 契约 C6：红态不许摘 read/bash —— 否则连自救都做不到，死锁不可逆。
 *
 * 依赖：只 import L0。
 */
import { DEFAULT_RULES } from "./L0-rules.js";

/**
 * @param {object} rules
 * @param {boolean} red  地基是否红
 * @returns {{deny: string[]}} 传给 ctx.tools.restrict() 的过滤器
 */
export function computeFilters(rules = DEFAULT_RULES, red = false) {
  const deny = [...rules.blockedTools];
  if (red) {
    for (const w of rules.writeTools) if (!deny.includes(w)) deny.push(w);
  }
  return { deny };
}

/** 红态下 bash 仍活着，用这些形态兜底拦写（有限集合，不是黑名单思维）。 */
export function bashWrites(rules = DEFAULT_RULES, cmd = "") {
  for (const pat of rules.bashWritePatterns) {
    if (new RegExp(pat).test(cmd)) return pat;
  }
  return null;
}
