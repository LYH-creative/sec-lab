-- L5 的库表结构。flag 值由 setup.sh 在容器起来后插进去（避免两处维护同一份内容）。

CREATE DATABASE IF NOT EXISTS secret;
USE secret;

CREATE TABLE IF NOT EXISTS flag (
  id  INT PRIMARY KEY,
  val VARCHAR(255) NOT NULL
);

-- 真实的缺陷：为了图省事建了个免密账号，而且 % 任意主机可连。
-- 空密码是本关能打通的关键 —— 因为 gopher 只发不收，拿不到服务端随机 salt，
-- 只有 auth_response 为 0 字节时，整个报文才能离线拼好。
CREATE USER IF NOT EXISTS 'ssrf'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'ssrf'@'%';
FLUSH PRIVILEGES;
