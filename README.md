# Cladue 聊天

端對端加密、資料只存在本機的文字聊天室。純靜態網頁，可放在 GitHub Pages，手機可「加到主畫面」當 App 使用（PWA）。

## 架構

```
手機/電腦 A ──(密文)──> 公共 MQTT 中繼伺服器 ──(密文)──> 手機/電腦 B
   │ IndexedDB                (只轉送、不保存)                 │ IndexedDB
   └ 聊天紀錄只存這裡                                          └ 聊天紀錄只存這裡
```

- **GitHub Pages**：只提供網頁程式，不存任何聊天資料。
- **中繼伺服器**：預設同時連 `broker.emqx.io` 與 `test.mosquitto.org`（WebSocket over TLS），互為備援。只轉送 AES-256-GCM 密文，伺服器看不到內容、也不保留訊息。
- **本機儲存**：瀏覽器 IndexedDB。換手機請用「匯出備份 / 匯入備份」。

## 怎麼做到「只有我的人進得來」

| 功能 | 做法 |
|---|---|
| 聊天室 | 「代號＋密碼」決定頻道位址與加密金鑰（PBKDF2）。密碼不同 → 不同頻道且解不開，同網站其他人看不到 |
| 裝置唯一碼 | 第一次開啟時產生 ECDH P-256 金鑰對，ID 碼＝公鑰雜湊（12 碼，如 `FGAF-HQRN-52J7`）。瀏覽器無法讀取手機 IMEI，所以用這個代替 |
| 加好友 | 輸入或掃 QR Code → 送出邀請 → 對方同意。雙方驗證「公鑰雜湊＝ID 碼」防冒充，之後私訊用 ECDH 共享金鑰加密 |
| 邀請進聊天室 | ① 對好友直接送加密邀請（對方點「加入聊天室」）② 分享邀請連結 / QR Code（LINE 等），連結的密碼在 `#` 後面，不會送到任何伺服器 |

## 部署到 GitHub Pages

1. 在 GitHub 建一個 repo（例如 `cladue-chat`），把本資料夾所有檔案推上去（含 `lib/`）。
2. Repo → Settings → Pages → Source 選 `Deploy from a branch`，Branch 選 `main` / `/ (root)` → Save。
3. 約 1 分鐘後網址為 `https://<你的帳號>.github.io/cladue-chat/`。
4. 手機用 Chrome / Safari 開啟 → 「加到主畫面」即可當 App 使用。

> 必須用 https（或 localhost）開啟，因為加密 API 只在安全環境可用。

## 限制

- 沒有雲端主機：**App 要開著（可在背景）才收得到訊息**。對方離線時，好友邀請 / 私訊 / 聊天室邀請會每 30 秒重送，雙方都上線時送達（最多保留 7 天）。
- 聊天室歷史：新成員或離線回來的人，只要聊天室裡有其他人在線，會自動補最近 300 則。
- 手機鎖屏久了瀏覽器會暫停網頁，iOS 尤其明顯；沒有推播（推播需要伺服器）。
- 公共中繼伺服器是免費服務，不保證永遠可用；可在「我的資料 → 中繼伺服器」改成自己的（例如自架 EMQX / Mosquitto 或 HiveMQ Cloud 免費方案）。所有人至少要有一台相同的伺服器。
- 公司網路（Cloudflare One 等）是否放行，取決於公司的政策；已在公司電腦實測 `broker.emqx.io:8084`、`test.mosquitto.org:8081` 可連線。若被擋，換成走 443 埠的伺服器最保險。

## 檔案

| 檔案 | 說明 |
|---|---|
| `index.html` | 介面與樣式（自動深色模式） |
| `app.js` | 全部邏輯：金鑰、加密、MQTT、好友、聊天室、同步、備份 |
| `lib/mqtt.min.js` | MQTT.js 5.10.1（本地化，不依賴 CDN） |
| `lib/qrcode.js` | qrcode-generator 1.4.4 |
| `sw.js`, `manifest.webmanifest`, `icon-*.png` | PWA（可安裝到手機主畫面、離線開啟） |
