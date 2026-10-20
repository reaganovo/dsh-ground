# dsh-ground · 地基（DSH 插件）

> 仓库名 `dsh-ground`；**npm 包名沿用 `keystone-ground`**（已装配在运行实例上，改名会断装）。

> **三条不变量钉在 DSH 原生接缝上：不满足 ⇒ 你没有那个能力，不是被提醒。**
> 契约在 [CONTRACT.md](CONTRACT.md)（先于代码存在）。改代码前先改契约。
> 服务器盘「开机就绪」预装（grub / GPU 驱动 / systemd 单元 / 4T 脚本）不看本文件，看 [BOOT.md](BOOT.md)。

## 装

```bash
# 1) 放代码
tar -xzf keystone-ground.tar.gz -C ~/projects/

# 2) 两处声明（缺一静默失效）
#    ~/.dsh/profiles/web/package.json  → dependencies + dsh.profile.bundles
ln -s ~/projects/keystone-ground ~/.dsh/profiles/web/node_modules/keystone-ground

# 3) 装配
#    ~/.dsh/profiles/web/cordis.patch.yml → - insert: {id: keystone-ground, name: keystone-ground}

# 4) 锁信任域（唯一要 sudo 的一步）
node src/index.js --lock          # 打印命令
sudo bash -c '…'                  # 执行

# 5) 验收
node src/index.js --selftest      # 17 条判据全绿
node src/index.js --health        # 门禁
```

## 命令

```bash
--selftest          契约自证（17 条：每条 1 正控 + 1 负控）
--health            门禁：现在红不红（微秒级，会话启动用这个）
--check             契约自证 + 门禁
--trust             信任域报告（C14）
--lock              打印锁权属命令（需 sudo）
--rot               腐烂报告（只读，不自动删）
--grants / --grant bash:<前缀> / --revoke <id>
--escape [分钟]     临时放行（须提权创建才生效）
```

## 分工（不重复造轮子）

| 面 | 谁管 |
|---|---|
| 历史不可改 | **DSH 原生** append-only + replay |
| 记忆 | **`dsh-memento`**（两轨两层 + 审批门 + 审计） |
| 中间产物清理 | **`dsh-janitor`**（5 级判定 + 永不自动删） |
| 判据 / 信任域 / 授权 | **本插件**（DSH 确认的空位） |

## 分层

```
L0-rules  L1-hot  L2-structure  L3-trust  L4-auth  L5-cold  L6-rot  index
 策略数据   热判决    结构摘除      信任域     授权     门禁+自证  腐烂   装配
```
依赖严格单向，已验证零反向。**加一条判据 = L0 加一行**，不动逻辑。

## 性能（实测）

| 项 | 值 |
|---|---|
| 热判决 | **0.32 µs/次** |
| 会话启动门禁 `--health` | 微秒级（不跑全量自证） |
| 额外进程 | **0**（全在 DSH 进程内） |

## 已知取舍

1. `restrict` 摘不掉 `bash` ⇒ 红态 bash 仍能写。故意：可自救优先于绝对禁写。
2. C14 防**意外**（幻觉/疲劳），不防**刻意**（操作者本来就有权）。
3. memento/janitor 的数据不受 C14 保护——它们存内容，不存控制面。

## 许可证

[Apache License 2.0](LICENSE) —— 可商用、可闭源使用，另加专利授权并要求声明改动。
安全类插件选它的理由：允许别人改造，但不允许悄悄改完还假装是同一个东西。
