# JSAtlas —— JavaScript Security Intelligence Engine
#
# 构建：
#   docker build -t jsatlas .
#
# 使用（本地文件挂进 /data）：
#   docker run --rm -v "$PWD:/data" jsatlas /data/app.js
#   docker run --rm -v "$PWD:/data" jsatlas /data/app.js --mode secret
#
# 使用（远程 URL）：
#   docker run --rm jsatlas https://example.com/static/app.js
#
# LLM 配置（AI 阶段，不配则降级为确定性结果）：
#   docker run --rm -e JSATLAS_LLM_API_KEY=sk-xxx jsatlas /data/app.js

FROM python:3.12-slim

WORKDIR /data

# 源码与元数据；README 若不在仓库中则生成占位文件
# （pyproject 的 readme 字段指向它，缺失会导致构建失败）
COPY pyproject.toml ./
COPY src ./src
RUN printf '# JSAtlas\n\nJavaScript Security Intelligence Engine\n' > README.md \
    && pip install --no-cache-dir ".[nltk,wordninja,schema,remote]"

# 入口即 CLI：docker run --rm -v "$PWD:/data" jsatlas <args>
# LLM 配置走标准环境变量（JSATLAS_LLM_API_KEY / _BASE_URL / _MODELS / _TIMEOUT），
# 也可把 jsatlas.config.json 放进挂载目录（查找顺序含当前目录）
ENTRYPOINT ["python", "-m", "jsatlas"]
CMD ["--help"]
