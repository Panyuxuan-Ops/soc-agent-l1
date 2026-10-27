FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN groupadd --system soc && useradd --system --gid soc --create-home soc

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY data ./data
COPY schemas ./schemas
COPY dify ./dify

# 运行期 trace / SQLite 写这里，避免覆盖镜像内的只读演示数据
RUN mkdir -p /app/runtime \
    && chown -R soc:soc /app

USER soc

EXPOSE 8000 8001 8002 8003

CMD ["python", "-m", "soc_agent", "--help"]
