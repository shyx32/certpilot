package secretbox

import (
	"bytes"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(mk)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := newBox(t)
	plain := []byte(`{"access_key_id":"LTAI...","access_key_secret":"s3cr3t"}`)
	aad := []byte("credential:42")

	sealed, err := b.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, plain) {
		t.Fatal("密文中出现了明文片段")
	}

	got, err := b.Open(sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("往返不一致: %q", got)
	}
}

// 密文被搬到另一条记录上时必须解不开。
func TestOpenRejectsWrongAAD(t *testing.T) {
	b := newBox(t)
	sealed, err := b.Seal([]byte("secret"), []byte("credential:42"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed, []byte("credential:43")); err == nil {
		t.Fatal("换了 AAD 仍能解密，认证数据没有生效")
	}
}

// 换一把主密钥必须解不开——这正是「拿到数据库也没用」的保证。
func TestOpenRejectsWrongMasterKey(t *testing.T) {
	sealed, err := newBox(t).Seal([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newBox(t).Open(sealed, nil); err == nil {
		t.Fatal("换了主密钥仍能解密")
	}
}

func TestSealUsesFreshDEK(t *testing.T) {
	b := newBox(t)
	a1, _ := b.Seal([]byte("same"), nil)
	a2, _ := b.Seal([]byte("same"), nil)
	if bytes.Equal(a1.Ciphertext, a2.Ciphertext) || bytes.Equal(a1.WrappedDEK, a2.WrappedDEK) {
		t.Fatal("两次加密产生了相同密文，DEK 或 nonce 被复用")
	}
}

func TestNewRejectsBadMasterKey(t *testing.T) {
	for _, k := range []string{"", "not-base64!!", "c2hvcnQ="} {
		if _, err := New(k); err == nil {
			t.Fatalf("主密钥 %q 应当被拒绝", k)
		}
	}
}
