package agent

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/artifacts"
)

// ctfCategoryPrompt returns specialized methodology guidelines based on challenge type.
func ctfCategoryPrompt(challenge string, files []artifacts.Artifact) string {
	switch strings.ToLower(strings.TrimSpace(challenge)) {
	case "misc":
		return `
【Misc（杂项安全）专精求解指引】
核心思路：快速定性文件真实格式与隐藏结构，逐层提取，避免在非关键数据上无效耗时。
1. 文件初检与元数据：
   - 优先使用 "file <文件>" 与 "head -c 32 <文件> | xxd" 检查真实魔数（Magic Number），严禁仅凭文件后缀判断格式。
   - 使用 "exiftool" 审查图片、音频与文档元数据（Comment、GPS、Author 等常藏隐写线索）。
   - 使用 "binwalk -e" 或 "foremost" 检测并分离尾部追加数据、内嵌压缩包或次级文件。
2. 压缩包与嵌套分析：
   - Zip 伪加密：若解压提示密码但题目无密码提示，优先用 Python 或十六进制工具检查全局/局部加密标记（09 00 -> 00 00）。
   - CRC32 爆破与明文攻击：单文件较小（<=6 字节）可直接 CRC32 碰撞；已知压缩包内部分文件时可用 bkcrack 进行明文攻击；常规弱密码使用 fcrackzip 快速爆破。
3. 隐写术（Steganography）：
   - 图片隐写：PNG 检查 LSB（zsteg -a）、异常 IDAT 数据块、宽高 CRC 校验错误；JPG 检查 JPHide/steghide/outguess；BMP/GIF 逐帧/通道分离。
   - 音频隐写：WAV/MP3 检查频域图（Spectrogram）、波形高低位或 MP3Stego。
   - Office 文档隐写（docx/xlsx/pptx）：本质为 zip 压缩包，解压后重点检索 word/document.xml、隐藏文字、白色文字、宏（vba）、rels 引用的外部资源。
4. 流量分析与取证：
   - PCAP/PCAPNG：使用 "tshark -r <file> -q -z conv,ip" 统计会话；导出 HTTP/FTP 传输对象；过滤追踪 TCP 流；提取 USB 键鼠数据包还原击键或光标轨迹。
   - 内存镜像：使用 volatility 检测 profile、查看 pslist/cmdline、dump 关键进程或桌面截屏。
5. 编码转换与条形码：
   - 常见编码组合：Base全家桶（Base64/32/58/85/91/92）、Hex、Unicode、JSFuck/Brainfuck、Morse 电码。
   - 二维码/条码：残缺二维码编写 Python/PIL 脚本补全定位角后再行识别。
6. 大体积文件规范：
   - 解压超过 64 MiB 的大型中间产物必须解压至 /tmp 下分析，严禁将未压缩的庞大临时数据保存在 /work，仅保留最终解题脚本与关键提炼数据。`

	case "crypto":
		return `
【Crypto（密码学）专精求解指引】
核心思路：优先判断密码体系（经典密码 vs 现代公钥 vs 对称密码 vs 伪随机），在 /work 编写 Python 脚本调用标准数学库快速求解。
1. 经典密码与编码：
   - 单表替换、凯撒/移位（ROT13）、维吉尼亚（Vigenere）、培根、仿射密码（Affine）、栅栏密码（Rail Fence）。
   - 复合嵌套编码：Base64/Hex 多层嵌套，编写 Python 循环解包。
2. 现代公钥密码（RSA / ECC / 离散对数）：
   - RSA 经典攻击向量：
     * 小公钥指数：e=3 且无 padding 直接开三次方根（gmpy2.iroot(c, 3)）；小 padding 考虑 CopperSmith 相关攻击。
     * 模数 N 分解：先调用 factordb API 尝试分解；若多组 N 共享素因数，使用 math.gcd(N1, N2)。
     * 私钥 d 过小：e 较大（与 N 同阶）时使用 Wiener 连分数攻击或 Boneh-Durfee 攻击。
     * 共模攻击：同一明文在相同 N、互质指数 e1, e2 下加密，利用扩展欧几里得定理还原。
     * 已知高位/低位：CopperSmith 寻找小根还原 p 或私钥。
   - 椭圆曲线（ECC）：小阶点穷举、Smart's Attack、Pohlig-Hellman（平滑阶）、Baby-step Giant-step。
3. 对称密码与哈希：
   - AES / DES：ECB 模式重放与拼接；CBC 模式字节翻转攻击（Bit-flipping）、Padding Oracle 填充提示攻击。
   - 哈希弱点：MD5/SHA1 弱哈希查彩虹表；哈希长度扩展攻击（HashPump）。
4. 伪随机数发生器（PRNG）：
   - Python random 模块（MT19937）：已知连续 624 个 32-bit 输出可用 RandCrack 还原内部状态，预测后续随机数。
   - 线性同余发生器（LCG）：已知连续若干输出通过求解线性同余方程组恢复参数。
5. 求解环境优先：
   - 优先在 /work 下创建 Python 脚本并使用 sympy、gmpy2、pycryptodome 求解，尽量避免盲目纯暴力搜索。`

	case "reverse":
		return `
【Reverse（逆向工程）专精求解指引】
核心思路：确认目标架构与混淆层，动静结合，提取校验逻辑或使用约束求解器自动化求解。
1. 架构与加壳检测：
   - 运行 "file" 确认二进制架构（ELF 32/64、PE x86/x64、ARM、MIPS）与链接方式；"strings" 提取明文字符串与导入函数。
   - 查壳脱壳：UPX 壳优先尝试 "upx -d"；如被抹去特征先手动修复特征头再脱壳。
2. 静态分析与反编译：
   - 使用 Ghidra 后台无头分析（ctf_run_background）反编译，或通过 objdump 反汇编。
   - 定位 main 函数与关键校验函数，梳理输入变换逻辑与常量数组。
3. 约束求解器自动化：
   - 面对复杂的逐字节变换、线性混淆或约束方程组，优先使用 Python z3-solver 建立模型求解输入，避免手工人肉反推。
4. 动态调试与内存提取：
   - 遇动态解密、SMC（Self-Modifying Code）或反反编译花指令，使用 gdb 在关键校验处下断点，直接从内存 dump 解密后的代码或 Flag。
5. 中间语言与字节码：
   - Python pyc：使用 pycdc (decompyle++) 或 uncompyle6 还原为源码。
   - Java / Android：使用 jadx 或 dex2jar 反编译。
   - .NET：使用 ilspycmd 反编译。`

	case "pwn":
		return `
【Pwn（二进制漏洞利用）专精求解指引】
核心思路：严格检查保护机制，定位内存破坏原语，编写本地与远程通用的 exploit 脚本。
1. 保护机制检查：
   - 必须先运行 "checksec <binary>" 确认保护机制：Canary、NX、PIE、RELRO。
2. 远程靶机探测与 PoW 排查：
   - 向远程靶机发送 exploit 前，先使用 ctf_probe_target 探测连通性并检查是否包含工作量证明（PoW）校验。
3. 常见漏洞利用路径：
   - 栈溢出：定位返回地址偏移（cyclic / cyclic -l）；无保护时构造 ret2text / ret2shellcode；开启 NX 构造 ROP 链（ROPgadget / pwntools ROP）。
   - 信息泄露：利用 puts/printf 泄露 libc 基址，通过已知 libc 或 LibcSearcher 定位 system 和 "/bin/sh" 构造 ret2libc。
   - 格式化字符串：%p 泄露栈/Canary/libc；%n 实现任意地址写。
   - 堆漏洞：UAF、Off-by-one、Fastbin dup、Tcache poisoning；结合 IO_FILE 攻击。
4. 利用脚本规范：
   - 必须使用 "from pwn import *" 编写独立 exploit 脚本保存在 /work；支持通过参数在本地 process() 与远程 remote() 之间无缝切换。
   - 多轮交互输入可结合 ctf_session_* 维护持久 PTY 会话。`

	case "web":
		return `
【Web（Web 安全）专精求解指引】
核心思路：优先轻量请求与源码审计，避免盲目重型扫描；针对性构造 exploit 脚本。
1. 轻量化请求优先：
   - 优先使用 ctf_http 工具测试目标 HTTP 响应头、Cookie、页面内容及回显，严禁无针对性盲目发起重型目录爆破。
2. 源码审计与敏感泄露：
   - 检查源码泄露：.git/、.svn/、.DS_Store、备份文件（.index.php.swp、www.zip）。
   - PHP 特性审计：extract() 变量覆盖、弱类型比较（== vs ===）、md5 0e 绕过、PHP 伪协议（php://filter/read=convert.base64-encode/resource=...）、反序列化 POP 链构造。
3. 常见漏洞利用链：
   - 注入类：SQL 注入（联合查询、报错注入、盲注）、SSTI 模板注入（Jinja2/Twig/Smarty 从 RCE 读取 flag）。
   - 身份伪造：JWT 弱密钥爆破或 none 算法绕过、Session 伪造。
   - SSRF 与命令注入：SSRF 探测内部端口与 Gopher 协议利用；命令注入绕过黑名单（${IFS}、拼接）。
4. 验证与 Flag 提取：
   - 编写 Python requests 脚本精准触发漏洞链并打印响应，系统将自动从响应输出中提取并登记 Flag。`

	default: // "auto" or empty
		return ctfAutoPrompt(files)
	}
}

// ctfAutoPrompt infers the most likely challenge domain from uploaded attachments.
func ctfAutoPrompt(files []artifacts.Artifact) string {
	miscCount := 0
	cryptoCount := 0
	reCount := 0
	pwnCount := 0

	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f.Name))
		base := strings.ToLower(f.Name)
		switch ext {
		case ".zip", ".tar", ".gz", ".7z", ".rar", ".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".wav", ".mp3", ".docx", ".xlsx", ".pptx", ".pdf":
			miscCount++
		case ".sage", ".pem", ".key":
			cryptoCount++
		case ".elf", ".so", ".exe", ".dll", ".pyc", ".class":
			reCount++
		}
		if strings.Contains(base, "crypto") || strings.Contains(base, "rsa") || strings.Contains(base, "cipher") || strings.Contains(base, "enc") {
			cryptoCount++
		}
		if strings.Contains(base, "pwn") || strings.Contains(base, "vuln") {
			pwnCount++
		}
		if strings.Contains(base, "misc") || strings.Contains(base, "look") || strings.Contains(base, "stego") {
			miscCount++
		}
	}

	var hint string
	if miscCount > 0 && miscCount >= cryptoCount && miscCount >= reCount {
		hint = "【题型初判：Misc 倾向】附件包含压缩包/媒体文件/文档，建议优先参考 Misc（杂项）思路：检查真实魔数、exiftool 元数据、binwalk 分离、LSB/频域隐写、Zip 伪加密与 Office 文档解压提取。"
	} else if cryptoCount > 0 && cryptoCount >= miscCount && cryptoCount >= reCount {
		hint = "【题型初判：Crypto 倾向】附件包含密码学相关文件或密文，建议优先参考 Crypto 思路：分析加密体制、RSA 攻击向量（低指数/因数分解/共模等）、离散对数或经典编码，编写 Python 脚本调用 gmpy2/sympy 求解。"
	} else if pwnCount > 0 {
		hint = "【题型初判：Pwn 倾向】检测到 Pwn 题型特征，建议优先使用 checksec 排查二进制保护机制，结合 ctf_probe_target 探测远程靶机与 PoW，利用 pwntools 编写 exploit 脚本。"
	} else if reCount > 0 {
		hint = "【题型初判：Reverse 倾向】附件包含二进制/字节码文件，建议优先运行 file 确认架构，UPX 查壳脱壳，结合 Ghidra 逆向或 Python z3-solver 自动化求解校验逻辑。"
	} else {
		hint = "【题型初判：通用分析】未检测到单一固定特征。请先运行 file/strings 确认附件类型，或探测远程目标端口，明确题型后再针对性展开。"
	}

	return fmt.Sprintf(`
【自动分析题型启发指引】
当前任务设定为自动识别题型。
%s
请根据实际发现，灵活套用 Web、Pwn、Reverse、Crypto、Misc 相应专精策略，保持解题路径最短。`, hint)
}
