#!/usr/bin/env bash
# 真机接线自证：在真 dsh 进程里加载 keystone-ground。
set -uo pipefail
export PATH="$HOME/.local/node/bin:$PATH"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAIL=0
ck() { if eval "$2"; then echo "  [ ok ] $1"; else echo "  [FAIL] $1"; FAIL=1; fi; }

node "$ROOT/src/index.js" --selftest >/dev/null 2>&1
ck "契约自证退 0（29 条）" "[ $? -eq 0 ]"

cat > "$TMP/patch.yml" <<YML
- insert:
    - id: keystone-ground
      name: $ROOT
YML
dsh --profile web --patch "$TMP/patch.yml" --dump-config >"$TMP/dump.txt" 2>/dev/null
ck "--dump-config 退 0（配置树能组装）" "[ $? -eq 0 ]"
ck "配置树含 keystone-ground" "grep -q 'keystone-ground' '$TMP/dump.txt'"

node -e "import('$ROOT/src/index.js').then(m=>process.exit(m.name==='keystone-ground'&&Array.isArray(m.inject)&&typeof m.apply==='function'?0:1)).catch(()=>process.exit(1))"
ck "模块导出 name/inject/apply" "[ $? -eq 0 ]"

DSH_HOME="$TMP/dsh" node -e "
process.env.DSH_HOME='$TMP/dsh'; process.env.KEYSTONE_GROUND_DIR='$TMP/dsh/ground';
import('$ROOT/src/index.js').then(m=>{ m.apply({on(){},logger:{}},{}); process.exit(require('node:fs').existsSync('$TMP/dsh/ground/rules.json')?0:1); })"
ck "首次装配自动落 rules.json" "[ $? -eq 0 ]"
if [ $FAIL -eq 0 ]; then echo "E2E=GREEN"; else echo "E2E=RED"; fi
exit $FAIL
