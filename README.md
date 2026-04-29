# 基于生物信息验证的涉密信息管理系统

本项目为毕业设计系统，已完成模块1-12交付，当前版本为“系统整合与全局测试”完成版。

核心目标：
1. 构建“身份认证 + 细粒度权限 + 文件加密 + 审计追踪”一体化系统
2. 支持管理员与普通用户分权使用
3. 在模块12阶段完成整合回归、安全测试、性能测试与文档收口

## 1. 技术栈

### 1.1 后端
1. Python 3.11
2. Flask
3. Flask-SQLAlchemy / SQLAlchemy 2.x
4. PyMySQL

### 1.2 安全与算法
1. AES-256-CBC（文件与生物模板加密）
2. bcrypt（密码哈希）
3. OpenCV / dlib / face-recognition（人脸）
4. OpenCV + minutiae 特征提取（指纹）

### 1.3 前端
1. Jinja2 模板
2. 原生 HTML / CSS / JavaScript
3. 基于 `base.html` 的统一页面壳层

### 1.4 数据库
1. MySQL 8.0+
2. 核心表：`customer`、`administrator`、`biometric_data`、`secret_file`、`audit_log`

## 2. 功能特点

### 2.1 认证与授权
1. 管理员账号管理普通用户
2. 用户登录采用口令 + 人脸 + 指纹串行双因子流程
3. ABAC（用户安全级别 + 文件密级）实现访问控制

### 2.2 涉密文件管理
1. 文件上传自动加密入库
2. 文件下载自动解密
3. 版本控制（主版本.次版本）
4. 历史版本可追溯
5. 回收站与彻底删除流程

### 2.3 密钥与审计
1. 每条文件记录独立密钥（`keys/<file_id>.key`）
2. 审计日志覆盖认证、权限、文件操作全过程
3. 日志查询、分页与 CSV 导出
4. 代码层 + 数据库层限制日志篡改

### 2.4 模块12新增交付
1. 全局整合回归脚本
2. 安全回归脚本（SQL注入/XSS/越权）
3. 性能基准脚本（页面响应、上传下载吞吐）
4. 系统使用说明与答辩演示流程文档

## 3. 目录结构（关键部分）
```text
.
├─ app/
│  ├─ models/
│  ├─ routes/
│  ├─ services/
│  ├─ static/
│  └─ templates/
├─ docs/
│  ├─ SYSTEM_USER_GUIDE.md
│  ├─ DEFENSE_DEMO_FLOW.md
│  └─ MODULE12_TEST_REPORT.md
├─ tests/
│  ├─ module5_runtime_check.py
│  ├─ module8_runtime_check.py
│  ├─ module9_runtime_check.py
│  ├─ module10_runtime_check.py
│  ├─ module11_runtime_check.py
│  ├─ module12_integration_check.py
│  ├─ module12_security_check.py
│  ├─ module12_performance_check.py
│  └─ module12_full_check.py
├─ init_db.py
├─ insert_admin.py
├─ upgrade_module8.py
├─ upgrade_module9.py
├─ upgrade_module11.py
├─ upgrade_module13.py
└─ app.py
```

## 4. 快速开始

### 4.1 克隆与安装
```bash
# 可选：git clone <your_repo>
cd 项目目录

conda create -n classified_system_env python=3.11 -y
conda activate classified_system_env
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4.2 配置环境变量
```bash
copy .env.example .env
```

在 `.env` 中填写：
1. 数据库连接参数
2. `SECRET_KEY`
3. `AES_KEY_B64`

### 4.3 初始化数据库
```bash
python init_db.py
python insert_admin.py
```

默认管理员：
1. 用户名：`admin`
2. 密码：`admin123`

### 4.4 旧库升级（建议执行）
```bash
python upgrade_module8.py
python upgrade_module9.py
python upgrade_module11.py
python upgrade_module13.py
```

### 4.5 启动项目
```bash
python app.py
```

访问地址：
1. 首页：`http://127.0.0.1:5000/`
2. 登录页：`http://127.0.0.1:5000/login`

## 5. 测试与验证

### 5.1 运行模块12全量回归（推荐）
```bash
python -X faulthandler tests/module12_full_check.py
```

该命令将自动执行：
1. 数据库预初始化/预升级
2. 模块5/8/9/10/11回归
3. 模块12整合、安全、性能测试

### 5.2 单项测试命令
```bash
python -X faulthandler tests/module12_integration_check.py
python -X faulthandler tests/module12_security_check.py
python -X faulthandler tests/module12_performance_check.py
```

## 6. 文档索引
1. 系统使用说明：`docs/SYSTEM_USER_GUIDE.md`
2. 答辩演示流程：`docs/DEFENSE_DEMO_FLOW.md`
3. 模块12测试报告：`docs/MODULE12_TEST_REPORT.md`

## 7. 常见问题
1. 启动失败优先检查 `.env` 与 MySQL 服务状态
2. 权限不足通常由 ABAC 规则导致，需要管理员调整用户级别或文件密级
3. 解密失败通常与 `keys` 目录中文件密钥缺失相关，可先执行升级脚本并检查日志

## 8. 许可与说明
本仓库为毕业设计用途。若用于生产环境，请补充：
1. HTTPS 与反向代理部署
2. 更严格的会话和密钥管理策略
3. CI 自动化与监控告警体系
