#!/usr/bin/env bash
# 定时积累可达性快照：数据集的价值全在"同一套测法、不同时间"，
# 而这件事必须无人值守地跑，否则只会在有人写文章的那天才想起来测一次。
# 每天两次（05:30 / 17:30），跑完重算 INDEX.md；周一顺带推 GitHub。
set -u
export HOME=/home/user
cd /home/user/work/egress-matrix || exit 0
LOG=$HOME/vmai-notes/matrix_cron.log
python3 egress_matrix.py >/dev/null 2>>"$LOG" || { echo "$(date -Is) probe failed" >>"$LOG"; exit 0; }
python3 index_results.py >>"$LOG" 2>&1

# 只留最近 60 个快照，避免仓库无限膨胀
ls -1t results/matrix-*.json 2>/dev/null | tail -n +61 | xargs -r rm -f

if [ "$(date +%u)" = "1" ]; then
  python3 /home/user/work/gh_push.py . WhaleFYu/egress-matrix master \
    "data: 定时快照 $(date -u +%Y%m%d-%H%M) UTC + INDEX.md 重算" >>"$LOG" 2>&1
fi
