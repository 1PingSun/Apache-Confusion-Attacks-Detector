import gradio as gr
import re
import json

# 預定義的漏洞檢測規則
VULNERABILITY_PATTERNS = {
    "filename_confusion": {
        "path_truncation": [
            {
                "pattern": r'RewriteRule\s+["\']?[^"\']*\([^)]+\)[^"\']*["\']?\s+["\']?[^"\']*\$1[^"\']*["\']?',
                "risk": "High",
                "description": "路徑截斷攻擊：RewriteRule 允許攻擊者控制路徑，可透過 %3F 截斷",
                "example": "curl http://server/user/1Ping%2Fsecret.yml%3F"
            }
        ],
        "rewrite_flag_bypass": [
            {
                "pattern": r'RewriteRule\s+[^[]*\[.*H=application/x-httpd-php.*\]',
                "risk": "High", 
                "description": "RewriteFlag 規則誤導：可上傳惡意檔案並透過 %3F 執行",
                "example": "curl http://server/upload/shell.gif%3fooo.php"
            },
            {
                "pattern": r'RewriteRule\s+[^[]*\.php[^[]*\[.*H=',
                "risk": "Medium",
                "description": "基於副檔名的處理規則，可能被繞過",
                "example": "上傳 shell.gif，透過 shell.gif%3ftest.php 執行"
            }
        ],
        "auth_bypass": [
            {
                "pattern": r'<Files\s+["\']?[^"\']+\.php["\']?>\s*.*?AuthType',
                "risk": "High",
                "description": "單檔認證繞過：透過 %3F 可繞過 <Files> 認證",
                "example": "curl http://server/admin.php%3Fooo.php"
            },
            {
                "pattern": r'<Files[^>]*>\s*.*?(Deny from all|Require all denied)',
                "risk": "Medium", 
                "description": "檔案存取控制，可能被 %3F 繞過",
                "example": "直接存取被保護的檔案"
            }
        ]
    },
    "documentroot_confusion": {
        "dangerous_rewrites": [
            {
                "pattern": r'RewriteRule\s+["\']?\^/[^/]+/\([^)]+\)\$["\']?\s+["\']?/\$1',
                "risk": "Critical",
                "description": "DocumentRoot 混淆：可讀取系統任意檔案",
                "example": "curl http://server/html/etc/passwd%3F"
            },
            {
                "pattern": r'RewriteRule\s+["\']?\^/html/["\']?',
                "risk": "High",
                "description": "典型的 DocumentRoot Confusion 模式",
                "example": "curl http://server/html/usr/lib/cgi-bin/script.cgi%3F"
            },
            {
                "pattern": r'RewriteRule\s+["\']?\^/static/',
                "risk": "Medium",
                "description": "靜態資源重寫，可能洩漏檔案",
                "example": "嘗試存取 /static/../etc/passwd"
            }
        ]
    }
}

def analyze_apache_config_fast(apache_config):
    """快速分析 Apache 配置檔案（不使用 AI 模型）"""
    
    if not apache_config.strip():
        return "❌ 請提供 Apache 配置檔案內容"
    
    vulnerabilities = []
    risk_level = "Safe"
    
    # 分析 Filename Confusion
    for category, patterns in VULNERABILITY_PATTERNS["filename_confusion"].items():
        for pattern_info in patterns:
            matches = re.finditer(pattern_info["pattern"], apache_config, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            for match in matches:
                vulnerabilities.append({
                    "type": "Filename Confusion",
                    "subtype": category.replace("_", " ").title(),
                    "risk": pattern_info["risk"],
                    "location": match.group(0),
                    "description": pattern_info["description"],
                    "example": pattern_info["example"],
                    "line": apache_config[:match.start()].count('\n') + 1
                })
                
                # 更新風險等級
                if pattern_info["risk"] == "Critical":
                    risk_level = "Critical"
                elif pattern_info["risk"] == "High" and risk_level not in ["Critical"]:
                    risk_level = "High"
                elif pattern_info["risk"] == "Medium" and risk_level not in ["Critical", "High"]:
                    risk_level = "Medium"
    
    # 分析 DocumentRoot Confusion
    for category, patterns in VULNERABILITY_PATTERNS["documentroot_confusion"].items():
        for pattern_info in patterns:
            matches = re.finditer(pattern_info["pattern"], apache_config, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                vulnerabilities.append({
                    "type": "DocumentRoot Confusion",
                    "subtype": category.replace("_", " ").title(),
                    "risk": pattern_info["risk"],
                    "location": match.group(0),
                    "description": pattern_info["description"],
                    "example": pattern_info["example"],
                    "line": apache_config[:match.start()].count('\n') + 1
                })
                
                # 更新風險等級
                if pattern_info["risk"] == "Critical":
                    risk_level = "Critical"
                elif pattern_info["risk"] == "High" and risk_level not in ["Critical"]:
                    risk_level = "High"
                elif pattern_info["risk"] == "Medium" and risk_level not in ["Critical", "High"]:
                    risk_level = "Medium"
    
    # 生成報告
    return generate_report(vulnerabilities, risk_level, apache_config)

def generate_report(vulnerabilities, risk_level, config):
    """生成漏洞分析報告"""
    
    # 風險等級圖示
    risk_icons = {
        "Critical": "🔴",
        "High": "🟠", 
        "Medium": "🟡",
        "Low": "🟢",
        "Safe": "✅"
    }
    
    report = f"""# 🔍 **漏洞檢測結果**

**風險等級：** {risk_icons.get(risk_level, "❓")} **{risk_level}**

"""
    
    if not vulnerabilities:
        report += """
## ✅ **未發現已知的 Confusion Attacks 漏洞**

配置檔案看起來相對安全，但建議：
1. 仔細檢查所有 RewriteRule 規則
2. 確保認證機制正確配置
3. 定期進行安全審查

"""
        return report
    
    # 按類型分組漏洞
    vuln_by_type = {}
    for vuln in vulnerabilities:
        vuln_type = vuln["type"]
        if vuln_type not in vuln_by_type:
            vuln_by_type[vuln_type] = []
        vuln_by_type[vuln_type].append(vuln)
    
    report += "## 📋 **發現的潛在漏洞**\n\n"
    
    for vuln_type, vulns in vuln_by_type.items():
        report += f"### {vuln_type}\n\n"
        
        for i, vuln in enumerate(vulns, 1):
            risk_icon = risk_icons.get(vuln["risk"], "❓")
            report += f"""**{i}. {vuln["subtype"]}** {risk_icon}

- **風險等級：** {vuln["risk"]}
- **位置：** 第 {vuln["line"]} 行
- **程式碼：** `{vuln["location"]}`
- **風險描述：** {vuln["description"]}
- **攻擊範例：** `{vuln["example"]}`

"""
    
    # CTF 利用建議
    report += """## 🎯 **CTF 利用建議**

### 攻擊思路
"""
    
    if any(v["type"] == "Filename Confusion" for v in vulnerabilities):
        report += """
#### Filename Confusion 攻擊
1. **路徑截斷**：使用 `%3F` (?) 截斷 RewriteRule 中的路徑
2. **認證繞過**：對受保護的 .php 檔案使用 `filename.php%3Fany.php` 
3. **檔案上傳利用**：上傳 .gif 檔案，透過 `file.gif%3Ftest.php` 執行
"""
    
    if any(v["type"] == "DocumentRoot Confusion" for v in vulnerabilities):
        report += """
#### DocumentRoot Confusion 攻擊  
1. **任意檔案讀取**：嘗試存取系統檔案如 `/etc/passwd`
2. **原始碼洩漏**：讀取 CGI 腳本、PHP 配置檔案
3. **資訊收集**：探索 `/usr/share/` 下的敏感檔案
"""
    
    # 常見目標檔案
    report += """
### 常見攻擊目標

#### 系統檔案
- `/etc/passwd` - 系統使用者資訊
- `/etc/shadow` - 密碼雜湊（需要權限）
- `/proc/self/environ` - 環境變數

#### Web 應用檔案  
- `config.php` - 資料庫配置
- `.htpasswd` - HTTP 認證檔案
- `web.xml` - Java 應用配置

#### CGI/腳本檔案
- `/usr/lib/cgi-bin/` - CGI 腳本目錄
- `/var/www/cgi-bin/` - Web CGI 目錄

### Payload 範例
"""
    
    for vuln in vulnerabilities[:3]:  # 只顯示前3個範例
        report += f"- `{vuln['example']}`\n"
    
    report += """
## ⚠️ **修復建議**

1. **限制 RewriteRule 範圍**：避免使用過於寬泛的正則表達式
2. **使用 Directory 指令**：取代 Files 指令進行存取控制  
3. **輸入驗證**：對 RewriteRule 的輸入進行嚴格驗證
4. **最小權限原則**：限制 Apache 使用者的檔案存取權限
5. **定期更新**：保持 Apache 版本更新

---
*此分析基於已知的 Confusion Attacks 模式，建議結合手動測試進行驗證*
"""
    
    return report

# 建立 Gradio 介面
def create_interface():
    with gr.Blocks(
        title="Apache Confusion Attacks 檢測器 - 快速版",
        theme=gr.themes.Soft(),
        css="""
        .container { max-width: 1200px; margin: auto; }
        .header { text-align: center; padding: 20px; }
        .info { background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px; padding: 10px; margin: 10px 0; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 10px; margin: 10px 0; }
        .result-container { 
            max-height: 600px; 
            overflow-y: auto; 
            padding: 15px; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            background-color: #fafafa;
        }
        .result-container h1 { color: #2c3e50; margin-top: 0; }
        .result-container h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .result-container h3 { color: #7f8c8d; }
        .result-container code { 
            background-color: #f1f2f6; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .result-container ul { margin-left: 20px; }
        .result-container li { margin-bottom: 8px; }
        """
    ) as demo:
        
        gr.Markdown("""
        # ⚡ Apache Confusion Attacks 檢測器 - 快速版
        
        這個工具專門檢測 Apache HTTP Server 配置檔案中的 Confusion Attacks 漏洞，包括：
        - **Filename Confusion**：路徑截斷、RewriteFlag 誤導、認證繞過
        - **DocumentRoot Confusion**：任意檔案讀取、原始碼洩漏
        
        特別適用於 CTF 競賽中的 Web 安全題目分析。
        """, elem_classes=["header"])
        
        gr.Markdown("""
        <div class="info">
        ⚡ <strong>極速分析</strong>
        <ul>
        <li>基於規則的快速檢測，秒級回應</li>
        <li>無需 AI 模型，100% 離線運行</li>
        <li>專門針對 Confusion Attacks 優化</li>
        </ul>
        </div>
        """)
        
        with gr.Row():
            with gr.Column(scale=2):
                apache_config = gr.Textbox(
                    label="📄 Apache 配置檔案內容",
                    placeholder="""請貼上您的 Apache 配置檔案內容，例如：

DocumentRoot /var/www/html
RewriteEngine On
RewriteRule "^/html/(.*)$" "/$1.html"

<Files "admin.php">
    AuthType Basic
    Require valid-user
</Files>""",
                    lines=15,
                    max_lines=25
                )
                
            with gr.Column(scale=1):
                gr.Markdown("""
                **檢測範圍：**
                - ✅ 路徑截斷攻擊
                - ✅ RewriteFlag 誤導
                - ✅ 認證繞過
                - ✅ DocumentRoot 混淆
                - ✅ 任意檔案讀取
                """)
                
                analyze_btn = gr.Button(
                    "⚡ 快速分析",
                    variant="primary",
                    size="lg"
                )
        
        # 分析結果區域
        with gr.Row():
            with gr.Column():
                result = gr.Markdown(
                    value="### 📋 分析結果\n\n點擊「⚡ 快速分析」開始檢測...",
                    elem_classes=["result-container"]
                )
                
                # 新增一個可複製的文本框
                with gr.Row():
                    show_text_btn = gr.Button("📄 顯示可複製純文字", size="sm", visible=False)
                    
                result_text = gr.Textbox(
                    label="📄 純文字結果（可複製）",
                    lines=8,
                    max_lines=15,
                    show_copy_button=True,
                    visible=False
                )
        
        def analyze_and_update(config):
            result_md = analyze_apache_config_fast(config)
            return [
                result_md,  # Markdown 顯示
                result_md,  # 文字版本
                gr.update(visible=True),  # 顯示按鈕
                gr.update(visible=False)  # 隱藏文字框
            ]
        
        def toggle_text_visibility(current_visibility):
            return gr.update(visible=not current_visibility)
        
        analyze_btn.click(
            fn=analyze_and_update,
            inputs=[apache_config],
            outputs=[result, result_text, show_text_btn, result_text]
        )
        
        show_text_btn.click(
            fn=lambda: gr.update(visible=True),
            outputs=result_text
        )
        
        # 範例配置檔案
        with gr.Row():
            with gr.Column():
                gr.Markdown("### 🧪 測試範例")
                
                example1 = gr.Button("範例 1: 高風險配置", size="sm")
                example2 = gr.Button("範例 2: 認證繞過", size="sm") 
                example3 = gr.Button("範例 3: DocumentRoot 混淆", size="sm")
        
        def load_example1():
            return """DocumentRoot /var/www/html
RewriteEngine On
RewriteRule "^/html/(.*)$" "/$1.html"
RewriteRule "^(.+\.php)$" "$1" [H=application/x-httpd-php]

<Files "admin.php">
    AuthType Basic
    AuthName "Admin Panel"
    Require valid-user
</Files>"""
        
        def load_example2():
            return """<Files "config.php">
    Order Allow,Deny
    Deny from all
</Files>

<FilesMatch ".+\.ph(?:ar|p|tml)$">
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>"""
        
        def load_example3():
            return """DocumentRoot /var/www/html
RewriteEngine On
RewriteRule "^/files/(.*)$" "/data/$1"
RewriteRule "^/static/(.*)$" "/$1"
RewriteRule "^(.*)\.(css|js|ico|svg)" "$1\.$2.gz" """
        
        example1.click(fn=load_example1, outputs=apache_config)
        example2.click(fn=load_example2, outputs=apache_config)
        example3.click(fn=load_example3, outputs=apache_config)
        
        gr.Markdown("""
        ---
        ### 📚 使用說明
        
        1. **貼上配置**：將 Apache 配置檔案內容貼到文字框中
        2. **點擊分析**：立即獲得詳細的漏洞分析報告
        3. **查看建議**：根據報告中的 CTF 利用建議進行測試
        
        ### 🎯 適用場景
        - ⚡ CTF 比賽快速分析
        - 🔍 Apache 配置安全審查  
        - 📚 Confusion Attacks 學習研究
        
        ### 🔧 技術特色
        - 基於正則表達式的模式匹配
        - 涵蓋所有已知的 Confusion Attacks 向量
        - 提供具體的 Payload 範例
        - 包含修復建議和最佳實踐
        """)
    
    return demo

# 啟動應用程式
if __name__ == "__main__":
    app = create_interface()
    app.launch()
