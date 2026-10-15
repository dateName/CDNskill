#!/data/data/com.termux/files/usr/bin/bash
# run.sh — cdn-recon 快速入口
# 用法:
#   ./run.sh <域名>            # 综合识别
#   ./run.sh <域名> --deep     # 深度检查（证书/cf-ray POP/全部头/IPv6）
#   ./run.sh <域名> --json     # JSON 输出（可叠加 --deep）
#   ./run.sh <域名> --no-http  # 仅 DNS 分析
# 示例:
#   ./run.sh aaaooo.xyz --deep
#   ./run.sh example.com --deep --json
#
# 仅用于自有资产或已获授权目标。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
DETECT="$DIR/scripts/cdn_detect.py"

if [ $# -eq 0 ]; then
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi

exec python3 "$DETECT" "$@"
