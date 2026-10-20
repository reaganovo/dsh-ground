/**
 * L0-rules —— 判据与规则**数据**（唯一真源）。
 *
 * 设计铁律：加一条判据 = 在这里加一行，**永远不动逻辑**。
 * 理由：判据会腐烂（C8/C9），把判据写进代码 = 每次调整都要改逻辑 = 引入回归。
 *
 * 依赖：只依赖 node 内置（path/os）。不许 import 本项目其它层（防止循环）。
 */
import os from "node:os";
import path from "node:path";

export const HOME = os.homedir();

/** 状态目录：判据真源与账本落这里。可被环境变量重定向（便于测试/多实例）。 */
export function stateDir() {
  return process.env.KEYSTONE_GROUND_DIR
    || path.join(process.env.DSH_HOME || path.join(HOME, ".dsh"), "ground");
}

/** 状态目录下的文件路径（L5/L6 共用，避免各写一份）。 */
export const stateFile = (f) => path.join(stateDir(), f);

/* ─────────────────────────── HOT 判据（每次工具调用，必须纯函数）───────────────────────────
 * 准入标准（契约 C1）：只收「拦错了也赔不起」的事。
 *   凭据泄露 → 不可逆 ⇒ 收
 *   破坏性命令 → 不可逆 ⇒ 收
 *   落点放错 → mv 即可 ⇒ **不收**（可逆的不进热路径）
 */
export const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "S1"],
  [/sk-[A-Za-z0-9_-]{20,}/, "S1"],
  [/(pass|api_k|access_t|secr)[a-z]*\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*_+./-]{6,}/i, "S1"],
];

/** 不可逆破坏命令。口径故意窄：只拦"几乎没有正当用途"的形态。 */
export const SYSTEM_DIRS = ["etc", "usr", "var", "boot", "opt", "sys", "proc", "bin", "lib", "sbin", "root"];
export const DESTRUCTIVE = [
  [/\brm\s+(?:-[a-zA-Z]+\s+)*(?:\/|\/\*)(?:\s|$)/, "S2"],
  [new RegExp("\\brm\\s+(?:-[a-zA-Z]+\\s+)*\\/(?:" + SYSTEM_DIRS.join("|") + ")\\b"), "S3"],
  [/\bsudo\s+(?:-\S+\s+)*(?:rm|chmod|chown|dd|mkfs|fdisk)\b/, "S2"],
  [/\bmkfs(?:\.\w+)?\s/, "S2"],
  [/\bch(?:mod|own)\s+(?:-[a-zA-Z]+\s+)*(?:777|a\+rwx)\s+\/\s*$/, "S4"],
];

/** 拦截文案：≤40 字节（契约 C3）。它进上下文，且必然引发一次重试。修法写 README。 */
export const WHY = {
  S1: "凭据明文，走凭据存储",
  S2: "不可逆破坏命令，先出清单",
  S3: "删系统目录，先出清单",
  S4: "全权限打根，先出清单",
  G: "已授权",
  I0: "判据失效，fail-closed",
};

/* ─────────────────────────── 结构层（从 schema 摘除，零 token）───────────────────────────
 * 为什么要"摘"而不是"拒"：摘掉 = 模型看不见 = 结构上不可能调用；
 *   拒绝 = 模型先花 token 规划、再吃一次失败、再恢复（实测 4-37% 仍会尝试）。
 */
export const DEFAULT_RULES = {
  version: 3,
  /** 委派类：永久摘除（子 agent 重复付费 + 击穿前缀缓存） */
  blockedTools: ["subagent", "subagent_fork", "workflow", "send_message", "interrupt_agent", "list_agents"],
  /** 写类：地基红时追加摘除（C6 留 read/bash 以便自救） */
  writeTools: ["write", "edit", "multiedit", "notebookedit", "present"],
  /** 红态下 bash 仍可写，故用这些形态兜底（有限，非黑名单思维） */
  bashWritePatterns: ["(^|[^>0-9])>{1,2}[^>&]", "\\btee\\b", "\\b(cp|mv|install|truncate)\\b"],

  /* C8 判据台账：每条必须标注 type + obsoleted_by（防"不死规则"） */
  gates: {
    S1: { type: "structural", obsoleted_by: null, why: "凭据泄露不可逆，与模型能力无关" },
    S2: { type: "structural", obsoleted_by: null, why: "破坏不可逆；权限门随模型变强更该留" },
    S3: { type: "structural", obsoleted_by: null, why: "删系统目录不可逆" },
    S4: { type: "structural", obsoleted_by: null, why: "全权限打根不可逆" },
    I0: { type: "structural", obsoleted_by: null, why: "判据失效必须 fail-closed" },
  },

  /* C9 腐烂：被评估 N 次但 0 拦截 ⇒ 进腐烂报告 */
  rot: { minEvals: 200, windowDays: 30 },

  /* 逃生舱：内容写死过期时刻（不看 mtime）+ 必须提权创建（C6/C14） */
  escapeMinutes: 30,
  /** 信任域：这两个文件是判据真源，必须对 agent 只读（C14） */
  trustPaths: ["rules.json", "grants.jsonl"],
  /** 账本：由守卫进程追加，agent 可读（留证不受影响） */
  ledgerFile: "ledger.jsonl",
  escapeFile: "allow.flag",
  grantsFile: "grants.jsonl",
  rulesFile: "rules.json",
};
