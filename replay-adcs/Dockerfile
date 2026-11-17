FROM python:3.12-alpine

# 只用标准库，不装任何 pip 包。
# 不用自己编译 MD4：alpine 的 OpenSSL 3 同样禁了 md4，ntlm.py 里手写了一份。
WORKDIR /app
COPY ntlm.py server.py ./
COPY flags /flags

ENV LAB_PORT=8080 \
    LAB_FLAG_DIR=/flags \
    PYTHONUNBUFFERED=1

EXPOSE 8080
CMD ["python3", "-u", "server.py"]
