package shell

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestAspnetNoEncodingRoundTrip 验证：显式 Encoding="none" 时，aspnet 客户端是否把原始 C# 明文
// （未经 base64、含 < > & 等字符）作为表单字段 x 发出，且靶机端能正确还原为源码并"执行成功"。
//
// 靶机端用 httptest 模拟 shell_aspx_eval.aspx 的解码回退逻辑：
//   - enc 非 hex/xor 时先试 Convert.FromBase64String，失败（FormatException）则回退用原文；
//   - 本项目 aspx 顶部 ValidateRequest="false"，故 < > & 不会被 IIS 拦截。
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func TestAspnetNoEncodingRoundTrip(t *testing.T) {
	var gotX, gotEnc, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		// 手动解析（避免 ReadAll 消费 body 后 r.ParseForm 读到空）
		v, _ := url.ParseQuery(gotBody)
		gotX = v.Get("x")
		gotEnc = v.Get("enc")

		// 复刻 aspx 解码：enc 非 hex/xor 时先试 base64，失败则回退用原文。
		src := gotX
		if gotEnc != "hex" && gotEnc != "xor" {
			if dec, err := base64.StdEncoding.DecodeString(gotX); err == nil {
				src = string(dec)
			}
		}

		// 从源码里抽出两个 R.Write("...") 的真实标记（裸 token，无 <START_ 前缀），原样回显，
		// 模拟 C# 的 R.Write(marker) 输出，让客户端 send 的 extract() 能截取出结果。
		re := regexp.MustCompile(`R\.Write\("([^"]+)"\)`)
		ms := re.FindAllStringSubmatch(src, -1)
		if len(ms) < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		startMark, endMark := ms[0][1], ms[1][1]

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(startMark + "{\"ok\":true}" + endMark))
	}))
	defer srv.Close()

	s := newAspnet()
	o := ExecOptions{Type: TypeAspnet, TargetURL: srv.URL, Param: "x", Encoding: "none"}
	res := s.Code(context.Background(), o, "public class WshRunner{}")

	t.Logf("server received enc=%q xLen=%d xHead=%q", gotEnc, len(gotX), truncate(gotX, 120))
	t.Logf("raw body len=%d head=%q", len(gotBody), truncate(gotBody, 200))

	if !res.OK {
		t.Fatalf("请求未成功: error=%q output=%q", res.Error, res.Output)
	}

	// 断言 1：靶机收到的 x 是原始 C# 明文（含 class 关键字与 WshRunner），而非 base64 密文。
	if !strings.Contains(gotX, "class WshRunner") {
		t.Fatalf("发送的并非未编码原文（可能仍为 base64）: %q", gotX)
	}
	// 断言 2：原文不含 base64 死板字符集特征（base64 不会出现空格+花括号的源码形态）。
	if strings.Contains(gotX, " ") == false {
		t.Fatalf("发出的内容不像 C# 源码: %q", gotX)
	}
	// 断言 3：靶机按回退逻辑用原文参与了"编译"（此处以标记回显代表执行成功）。
	if !strings.Contains(res.Output, "ok") {
		t.Fatalf("靶机未回显执行结果: %q", res.Output)
	}

	t.Logf("OK: 未编码请求成功, 靶机收到原文长度=%d, enc=%q", len(gotX), gotEnc)
}

// TestAspnetDefaultRaw 验证：不指定 Encoding 时，aspnet 默认直接发原始 C# 明文（不再 base64）。
// 靶机端收到 x 后应能直接看到 class WshRunner 源码；若仍是 base64 密文则本断言失败。
func TestAspnetDefaultRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		x := r.FormValue("x")
		// 默认应为明文源码：直接含 class WshRunner，而非 base64 密文。
		if !strings.Contains(x, "class WshRunner") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := newAspnet()
	o := ExecOptions{Type: TypeAspnet, TargetURL: srv.URL, Param: "x", Method: http.MethodPost} // 不指定 Encoding
	res := s.Code(context.Background(), o, "public class WshRunner{}")
	if !res.OK {
		t.Fatalf("默认行为应为明文且成功: %q", res.Error)
	}
}
