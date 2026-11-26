#!/usr/bin/env bash
# 定时积累可达性快照：数据集的价值全在"同一套测法、不同时间"，
# 而这件事必须无人值守地跑，否则只会在有人写文章的那天才想起来测一次。
# 每天两次（05:30 / 17:30），跑完重算 INDEX.md；周一顺带推 GitHub。
set -u
export HOME=/home/user
# cron 不继承登录 shell 的代理变量：不显式导出，探针就会走"没有解析器"的直连路径，
# 把 49 个端点全写成 DNS-FAIL（2026-11-26 05:30 那轮就是这么废掉的）。
export http_proxy="${http_proxy:-http://127.0.0.1:18081}"
export https_proxy="${https_proxy:-http://127.0.0.1:18081}"
export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy"
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"
export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-/usr/local/share/ca-certificates/local-net-proxy.crt}"
cd /home/user/work/egress-matrix || exit 0
LOG=$HOME/vmai-notes/matrix_cron.log
# --require-proxy：宁可不跑，也不写一张假表。不合格的轮次它会自己挪进 results/invalid/（退出码 3）。
python3 egress_matrix.py --require-proxy >/dev/null 2>>"$LOG"
rc=$?
if [ $rc -ne 0 ]; then
  echo "$(date -Is) probe exit=$rc（2=无代理拒跑，3=快照不合格已隔离）" >>"$LOG"
  [ $rc -eq 2 ] && exit 0
fi
python3 index_results.py >>"$LOG" 2>&1

# 第二个观测点：GitHub runner（干净公网）每天跑同一套探针，产物从仓库取回来。
# 有它才能把"这条判决属于端点"和"这条判决属于我的出口"分开。
curl -s -m 40 -x "${https_proxy:-http://127.0.0.1:18081}" \
  https://raw.githubusercontent.com/WhaleFYu/egress-matrix/master/results/vantage-github-latest.json \
  -o results/vantage-github-latest.json.tmp \
  && python3 -c "import json,sys; d=json.load(open('results/vantage-github-latest.json.tmp')); assert d.get('rows'); print('vantage ok', d.get('generated_at'), len(d['rows']))" >>"$LOG" 2>&1 \
  && mv results/vantage-github-latest.json.tmp results/vantage-github-latest.json \
  || rm -f results/vantage-github-latest.json.tmp

# 只留最近 60 个快照，避免仓库无限膨胀
ls -1t results/matrix-*.json 2>/dev/null | tail -n +61 | xargs -r rm -f

if [ "$(date +%u)" = "1" ]; then
  python3 /home/user/work/gh_push.py . WhaleFYu/egress-matrix master \
    "data: 定时快照 $(date -u +%Y%m%d-%H%M) UTC + INDEX.md 重算" >>"$LOG" 2>&1
fi
