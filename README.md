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

## 通知與未讀

| 功能 | 說明 |
|---|---|
| App 圖示未讀數 | 安裝成 App 後，圖示上顯示未讀總數（Badging API：Windows / macOS / Android 的 Chrome、Edge；iPhone 需 iOS 16.4+ 且從主畫面開啟、已允許通知） |
| 系統通知 | App 在背景或視窗沒有焦點時跳出通知，同一對話合併成一則並顯示未讀數；點通知直接開啟該對話 |
| App 內提示 | App 在前景、但正在看別的對話時，底部跳出可點的提示條 |
| 未讀標示 | 對話列表粗體＋紅色數字、分頁標題 `(N)`、手機版返回鍵旁顯示其他對話未讀數、開啟對話時顯示「以下為未讀訊息」分隔線 |
| 靜音 | 對話右上「⋯」可關閉該對話通知（列表改灰色數字，不計入 App 圖示未讀數） |
| 隱私 | 「我的資料 → 通知」可關閉通知中的訊息內容預覽 |

第一次開啟時，列表上方會提示開啟通知；iPhone 在 Safari 中會提示先「加入主畫面」。

## 推播伺服器（App 關閉時也能收到通知）

手機會在 App 切到背景後很快暫停網頁（iPhone 幾秒、Android 幾分鐘），沒有推播伺服器時就收不到訊息與通知。
`push-worker/worker.js` 是一支 Cloudflare Worker（免費方案即可），iPhone（iOS 16.4+ 主畫面 App）與 Android 共用：

```
傳送者 ──(已端對端加密的訊息)──> Cloudflare Worker ──(Web Push)──> Apple / Google / Microsoft 推播服務 ──> 收件者手機
                                    只存推播訂閱與頻道雜湊                                     Service Worker 在背景解密、
                                    看不到訊息內容                                             存進本機紀錄、跳通知、更新圖示未讀數
```

### 部署（全程在網頁後台操作，不用安裝任何東西）

1. 到 <https://dash.cloudflare.com> 註冊 / 登入（免費）。
2. 左側 **Storage & Databases → KV → Create**，名稱填 `cladue-push`。
3. 左側 **Compute (Workers) → Workers & Pages → Create → Start with Hello World**，名稱填 `cladue-push` → **Deploy**。
4. 進入該 Worker → **Edit code**，把 `push-worker/worker.js` 的內容整個貼上取代 → **Deploy**。
5. Worker 的 **Settings → Bindings → Add → KV namespace**：Variable name 填 **`SUBS`**，選剛剛建的 `cladue-push` → **Deploy**。
6. 用瀏覽器開 `https://cladue-push.<你的帳號>.workers.dev/vapid`，看到 `{"key":"B..."}` 就成功了。
7. 把網址 `https://cladue-push.<你的帳號>.workers.dev` 填到 `app.js` 的 `DEFAULT_PUSH`（所有人自動套用），或在 App「我的資料 → 推播伺服器」個別填入。

> 傳送者與收件者都要設定同一台推播伺服器；收件者需已開啟通知。
> 免費方案額度：每天 10 萬次請求、KV 每天 1000 次寫入（只有加入 / 離開聊天室、靜音時才寫入），一般小團體使用綽綽有餘。
> 單一聊天室推播上限 40 台裝置（免費方案每次請求最多 50 個對外連線）。

## 部署到 GitHub Pages

1. 在 GitHub 建一個 repo（例如 `cladue-chat`），把本資料夾所有檔案推上去（含 `lib/`）。
2. Repo → Settings → Pages → Source 選 `Deploy from a branch`，Branch 選 `main` / `/ (root)` → Save。
3. 約 1 分鐘後網址為 `https://<你的帳號>.github.io/cladue-chat/`。
4. 手機用 Chrome / Safari 開啟 → 「加到主畫面」即可當 App 使用。

> 必須用 https（或 localhost）開啟，因為加密 API 只在安全環境可用。

## 限制

- 沒有雲端主機：**App 要開著（可在背景）才收得到訊息**。對方離線時，好友邀請 / 私訊 / 聊天室邀請會每 30 秒重送，雙方都上線時送達（最多保留 7 天）。
- 聊天室歷史：新成員或離線回來的人，只要聊天室裡有其他人在線，會自動補最近 300 則。
- 手機鎖屏久了瀏覽器會暫停網頁，iOS 尤其明顯。**沒設定推播伺服器時**，App 被暫停或關閉就收不到通知；設定後即使 App 關閉也會收到（訊息太長放不進推播時，通知只顯示「傳來新訊息」，打開 App 後同步內容）。
- 公共中繼伺服器是免費服務，不保證永遠可用；可在「我的資料 → 中繼伺服器」改成自己的（例如自架 EMQX / Mosquitto 或 HiveMQ Cloud 免費方案）。所有人至少要有一台相同的伺服器。
- 公司網路（Cloudflare One 等）是否放行，取決於公司的政策；已在公司電腦實測 `broker.emqx.io:8084`、`test.mosquitto.org:8081` 可連線。若被擋，換成走 443 埠的伺服器最保險。

## 檔案

| 檔案 | 說明 |
|---|---|
| `index.html` | 介面與樣式（自動深色模式） |
| `app.js` | 全部邏輯：金鑰、加密、MQTT、好友、聊天室、同步、備份 |
| `lib/mqtt.min.js` | MQTT.js 5.10.1（本地化，不依賴 CDN） |
| `lib/qrcode.js` | qrcode-generator 1.4.4 |
| `sw.js`, `manifest.webmanifest`, `icon-*.png` | PWA（可安裝到手機主畫面、離線開啟、點通知開啟對話） |
| `badge-96.png` | Android 狀態列通知小圖示（白色單色） |
| `push-worker/worker.js` | 推播伺服器（Cloudflare Worker）：VAPID、Web Push 加密（RFC 8291）、訂閱管理 |
