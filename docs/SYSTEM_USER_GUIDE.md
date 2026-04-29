# 系统使用说明（模块12交付）

## 1. 文档目的
本说明用于指导系统从零部署到日常使用，覆盖：
1. 环境准备
2. 数据库初始化与升级
3. 管理员与普通用户操作流程
4. 常见问题处理（FAQ）

## 2. 运行环境要求

### 2.1 软件要求
1. Windows 10/11（已在 Windows 11 验证）
2. Python 3.11
3. MySQL 8.0+
4. Git（可选）

### 2.2 Python 依赖
项目依赖见 `requirements.txt`，包含：
1. Flask / SQLAlchemy / PyMySQL
2. cryptography（AES-256）
3. OpenCV / dlib / face-recognition / numpy（生物识别）

## 3. 环境准备

### 3.1 创建虚拟环境（示例：Anaconda）
```bash
conda create -n classified_system_env python=3.11 -y
conda activate classified_system_env
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3.2 配置环境变量
1. 复制 `.env.example` 为 `.env`
2. 填写数据库参数与密钥参数

关键项示例：
```env
DATABASE_HOST=localhost
DATABASE_PORT=3306
DATABASE_USER=root
DATABASE_PASSWORD=你的密码
DATABASE_NAME=classified_system

SECRET_KEY=请填入随机字符串
AES_KEY_B64=请填入32字节密钥的Base64
```

## 4. 数据库初始化与升级

### 4.1 首次初始化
```bash
python init_db.py
python insert_admin.py
```

默认管理员：
1. 用户名：`admin`
2. 密码：`admin123`

### 4.2 已有旧库升级（建议按顺序执行）
```bash
python upgrade_module8.py
python upgrade_module9.py
python upgrade_module11.py
```

说明：
1. `upgrade_module8.py`：补齐版本控制与回收站字段
2. `upgrade_module9.py`：迁移独立文件密钥机制
3. `upgrade_module11.py`：补齐审计防篡改字段并回填哈希链

## 5. 启动系统
```bash
python app.py
```

默认访问地址：
1. 首页：`http://127.0.0.1:5000/`
2. 登录页：`http://127.0.0.1:5000/login`

## 6. 管理员使用指南

### 6.1 登录
1. 访问 `/login`
2. 选择账号类型“管理员”
3. 输入管理员账号密码登录

### 6.2 用户管理
1. 进入“系统管理” -> 用户安全级别设置
2. 可执行：创建用户、调整用户安全级别、删除用户
3. 所有操作自动写入审计日志

### 6.3 文件密级管理
1. 进入“系统管理” -> 文件密级设置页
2. 可对文件分组进行密级升降（同步作用于历史版本）

### 6.4 审计日志管理
1. 进入“审计日志”页面
2. 支持按时间、操作者、操作类型、文件ID检索
3. 支持导出 CSV

## 7. 普通用户使用指南

### 7.1 登录（双因子串行认证）
1. 第一步：账号密码验证
2. 第二步：人脸活体+比对验证
3. 第三步：指纹比对验证
4. 三步全部通过后进入系统

### 7.2 文件操作
1. 在权限范围内上传文件（自动 AES-256 加密）
2. 查看、下载、更新文件版本
3. 查看历史版本并下载历史文件
4. 无权限密级会被系统拒绝并提示“权限不足”

## 8. 权限与安全规则
1. ABAC：按“用户安全级别 + 文件密级”判定访问
2. 文件密钥：每条文件记录独立密钥（`keys/<file_id>.key`）
3. 审计日志：代码层和数据库层禁止更新/删除
4. 安全响应头：统一配置 CSP、X-Frame-Options、X-Content-Type-Options

## 9. 运维建议
1. 定期备份 MySQL 数据库与 `keys` 目录
2. 生产环境启用 HTTPS，并将 `SESSION_COOKIE_SECURE=true`
3. 限制数据库账号权限，避免使用高权限账号直连业务库
4. 对审计日志导出文件进行分级保存与访问审计

## 10. FAQ

### Q1：启动时报数据库连接失败怎么办？
检查项：
1. MySQL 服务是否已启动
2. `.env` 中数据库主机、端口、用户名、密码是否正确
3. 数据库名是否存在（可先执行 `python init_db.py`）

### Q2：页面提示“权限不足”怎么办？
可能原因：
1. 当前账号安全级别不足
2. 正在访问管理员专属页面
3. 文件密级被管理员上调

处理建议：
1. 管理员在权限管理页核对用户安全级别
2. 管理员在文件密级页核对文件密级

### Q3：文件下载失败或提示解密失败？
检查项：
1. `keys` 目录中对应 `file_id.key` 是否存在
2. 是否执行过不完整迁移（可执行 `python upgrade_module9.py`）
3. 文件记录是否已被彻底删除

### Q4：审计日志页面无法打开或导出失败？
检查项：
1. 当前登录账号是否为管理员
2. 是否完成模块11升级（`python upgrade_module11.py`）
3. 数据库用户是否具备触发器相关权限

### Q5：如何快速做全量回归？
执行：
```bash
python -X faulthandler tests/module12_full_check.py
```

该脚本会自动执行数据库预升级与模块5/8/9/10/11/12的回归检查。
