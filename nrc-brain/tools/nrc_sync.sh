#!/usr/bin/env bash
# ============================================================
# nrc_sync.sh — 三台手机共享「NRC 适配大脑」（GitHub Contents API 版）
# ------------------------------------------------------------
# 为什么不用 git：proot Ubuntu 里 git 写对象会被 l2s.tmp 机制污染，push 必挂
# （bad pack / unpack 错误）。本脚本改走 GitHub REST Contents API（curl），
# 用手机里已登录的 Operit GitHub token，把你的公开 repo 当三机共享盘。
#
# 命令：
#   init    首次初始化（在 repo 建 nrc-brain/JOURNAL.md）
#   pull    拉取三机共享的 JOURNAL / 笔记 / 工具
#   push    上传本机产出 + 自动往 JOURNAL.md 追加一条
#   log     只看各机进展摘要
#   who     查看 token / repo 配置
#
# 用法（三台手机各做一次）：
#   export NRC_REPO=Leafvk/Action-Build
#   bash nrc_sync.sh init
#   bash nrc_sync.sh pull
#   bash nrc_sync.sh push "修完 KCFI，r98c 可跑"
# ============================================================
set -u

REPO="${NRC_REPO:-}"                         # 形如 Leafvk/Action-Build
WORK="${NRC_WORK:-$HOME/nrc-brain}"          # 本机工作副本
OPDATA=/data/data/com.ai.assistance.operit/files/datastore
ME="$(getprop ro.product.device 2>/dev/null || echo unknown)$(uname -m)"
KREL="$(uname -r)"
BRANCH="${NRC_BRANCH:-main}"

say(){ printf '%s\n' "$*"; }
die(){ say "ERROR: $*"; exit 1; }
need_repo(){ [ -n "$REPO" ] || die "先 export NRC_REPO=<你的公开repo>，例如 Leafvk/Action-Build"; }

get_token(){
  [ -r "$OPDATA/github_auth_preferences.preferences_pb" ] || return 1
  strings "$OPDATA/github_auth_preferences.preferences_pb" 2>/dev/null \
    | grep -oE 'gh[opsu]_[A-Za-z0-9]{20,}' | head -1
}
TOKEN="$(get_token || true)"
[ -n "${TOKEN:-}" ] || die "读不到 Operit 的 GitHub token（github_auth_preferences）。请先在 Operit 里登录 GitHub。"
API="https://api.github.com/repos/$REPO/contents"
H1="Authorization: Bearer $TOKEN"
H2="Accept: application/vnd.github+json"

# 取远端文件 sha（不存在返回空）
get_sha(){
  curl -sS -H "$H1" -H "$H2" "$API/$1" \
    | grep -oE '"sha": "[a-f0-9]{40}"' | head -1 | cut -d'"' -f4
}

# 下载远端文件到本地（存在返回 0）
fetch(){
  local b64
  b64="$(curl -sS -H "$H1" -H "$H2" "$API/$1" \
    | grep -oE '"content": "[A-Za-z0-9+/=\r\n]+"' | head -1 | cut -d'"' -f4)"
  [ -n "$b64" ] || return 1
  mkdir -p "$(dirname "$2")"
  printf '%s' "$b64" | tr -d '\r\n' | base64 -d > "$2" || return 1
}

# 上传/更新文件，回显 HTTP 状态码
put_file(){  # $1=远端相对路径  $2=本地路径  $3=message
  local sha b64 body
  sha="$(get_sha "$1" || true)"
  b64="$(base64 -w0 < "$2" 2>/dev/null || base64 < "$2" | tr -d '\n')"
  body="{\"message\":\"$(printf '%s' "$3" | sed 's/"/-/g')\",\"branch\":\"$BRANCH\",\"content\":\"$b64\""
  [ -n "$sha" ] && body="$body,\"sha\":\"$sha\""
  body="$body}"
  curl -sS -X PUT -H "$H1" -H "$H2" -d "$body" "$API/$1" -o /tmp/_nrc_put.json -w '%{http_code}'
}

do_init(){
  need_repo
  say "== init ($ME) =="
  mkdir -p "$WORK"
  local sha; sha="$(get_sha "nrc-brain/JOURNAL.md" || true)"
  if [ -z "$sha" ]; then
    printf '# NRC 内核适配 · 共享大脑（JOURNAL）\n\n> 各机 append-only 流水账，push 自动追加。\n\n---\n## 记录\n' > "$WORK/JOURNAL.md"
    code="$(put_file "nrc-brain/JOURNAL.md" "$WORK/JOURNAL.md" "init: create JOURNAL.md")"
    say "created nrc-brain/JOURNAL.md (HTTP $code)"
    [ "$code" = 201 ] || [ "$code" = 200 ] || die "创建失败，检查 repo 名/分支名（NRC_BRANCH）"
  else
    say "JOURNAL.md 已存在，直接 pull 即可"
  fi
  say "OK 工作副本 -> $WORK"
}

do_pull(){
  need_repo
  mkdir -p "$WORK"
  say "== pull ($ME) =="
  fetch "nrc-brain/JOURNAL.md" "$WORK/JOURNAL.md" \
    && say "  [ok] JOURNAL.md" || say "  [skip] JOURNAL.md（先跑 init）"
  fetch "nrc-brain/KERNEL_ADAPT_NOTES.md" "$WORK/KERNEL_ADAPT_NOTES.md" \
    && say "  [ok] KERNEL_ADAPT_NOTES.md" || true
  local names
  names="$(curl -sS -H "$H1" -H "$H2" "$API/nrc-brain/tools" \
    | grep -oE '"name": "[^"]+"' | cut -d'"' -f4)"
  for f in $names; do
    fetch "nrc-brain/tools/$f" "$WORK/tools/$f" && say "  [ok] tools/$f"
  done
  say "--- 各机进展摘要 ---"
  [ -f "$WORK/JOURNAL.md" ] && grep -E '^### \[' "$WORK/JOURNAL.md" | tail -20
}

do_push(){
  need_repo
  mkdir -p "$WORK"
  local msg="${1:-$ME update}"
  [ -f "$WORK/JOURNAL.md" ] || do_pull >/dev/null 2>&1 || true
  cd "$WORK"
  # 1) JOURNAL 追加一条
  {
    echo ""
    echo "### [$(date +%F)][$ME] $msg"
    echo "- 内核: $KREL"
    echo "- 结论: $msg"
    echo "- 记录者: $ME @ $(date +'%F %T')"
  } >> JOURNAL.md
  code="$(put_file "nrc-brain/JOURNAL.md" JOURNAL.md "$msg")"
  say "JOURNAL.md HTTP $code"
  [ "$code" = 200 ] || say "  (非 200，看 /tmp/_nrc_put.json)"
  # 2) 工具与笔记
  for f in KERNEL_ADAPT_NOTES.md tools/recalc_linker64_offsets.py tools/audit_kcfi.sh tools/nrc_sync.sh; do
    [ -f "$f" ] || continue
    code="$(put_file "nrc-brain/$f" "$f" "$msg")"
    say "  $f HTTP $code"
  done
  # 3) 本机源码快照（带机型前缀防冲突）
  if [ -d src ]; then
    for f in src/*; do
      [ -f "$f" ] || continue
      base="$(basename "$f")"
      code="$(put_file "nrc-brain/src/${ME}_$base" "$f" "$msg")"
      say "  src/${ME}_$base HTTP $code"
    done
  fi
  say "OK push 完成: $msg"
}

do_log(){
  need_repo
  mkdir -p "$WORK"
  fetch "nrc-brain/JOURNAL.md" "$WORK/JOURNAL.md" || die "JOURNAL 不存在（先 init）"
  grep -E '^### \[' "$WORK/JOURNAL.md" | tail -30
}

do_who(){
  echo "repo   : ${REPO:-<未设置  export NRC_REPO=...>}"
  echo "token  : ${TOKEN:0:7}... (len ${#TOKEN})"
  curl -sS -H "Authorization: Bearer $TOKEN" https://api.github.com/user \
    | grep -oE '"login": "[^"]+"' | head -1
  echo "me     : $ME / $KREL"
  echo "work   : $WORK"
}

case "${1:-}" in
  init) do_init ;;
  pull) do_pull ;;
  push) shift; do_push "${1:-$ME: update}" ;;
  log)  do_log ;;
  who)  do_who ;;
  *) cat <<EOF
用法: bash nrc_sync.sh <命令>
  init              首次初始化（建 nrc-brain/JOURNAL.md）
  pull              拉取三机共享资料 + 进展摘要
  push "<一句话>"    推送本机进展（自动追加 JOURNAL）
  log               只看各机进展摘要
  who               查看 token / repo 配置
环境变量:
  NRC_REPO=<你的公开repo>   例如 Leafvk/Action-Build（必须）
  NRC_BRANCH=main           默认 main
  NRC_WORK=~nrc-brain       本机工作副本
本机: $ME / $KREL
EOF
  ;;
esac