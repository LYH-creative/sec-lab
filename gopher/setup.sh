#!/usr/bin/env bash
# 一键起靶场：铺 flag、建上传目录、构建启动、灌数据
set -euo pipefail
cd "$(dirname "$0")"

# ---- 1. 把 flag 铺到各服务能读到的地方 -------------------------------------
# legacy 的两个实例是只读挂载，文件必须在 up 之前就位
cp -f flags/l1.flag legacy/public/l1.txt
cp -f flags/l2.flag legacy/internal/l2.txt

# ---- 2. L4 的落点目录 -------------------------------------------------------
mkdir -p src/uploads
touch src/uploads/.gitkeep
# redis 容器里的 uid 跟宿主机对不上，必须放开写权限
chmod 777 src/uploads

# ---- 3. 起 ------------------------------------------------------------------
docker compose up -d --build

# ---- 4. 等 MariaDB 起来再灌 L5 的 flag -------------------------------------
# 注意别用 mariadb-admin ping 探测：它在初始化还没结束时就能连上，
# 那时 root 密码还没落库，后面插数据会 Access denied。
printf '\n等待 mariadb 就绪'
for _ in $(seq 1 90); do
  if docker exec gopher-db mariadb -uroot -proot123 -e 'SELECT 1' >/dev/null 2>&1; then
    printf ' ok\n'
    break
  fi
  printf '.'
  sleep 1
done

docker exec -i gopher-db mariadb -uroot -proot123 secret <<SQL
DELETE FROM flag WHERE id = 1;
INSERT INTO flag (id, val) VALUES (1, '$(tr -d '\n' < flags/l5.flag)');
SQL

# ---- 5. L3 的 flag 塞进 redis ----------------------------------------------
docker exec gopher-redis redis-cli SET l3_flag "$(tr -d '\n' < flags/l3.flag)" >/dev/null

cat <<'EOF'

──────────────────────────────────────────────
  web            http://127.0.0.1:8896/
  legacy-public  gopher://127.0.0.1:7070/   (L1)
  redis / db / fpm / legacy-internal  不映射端口，只能从容器网络打
──────────────────────────────────────────────
EOF
