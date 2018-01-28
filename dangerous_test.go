package dangerous

import (
	"testing"
	"time"
)


func TestDangerous_Sign(t *testing.T) {
	message := "hello world"

	expected := "aGVsbG8gd29ybGQulTKLm6tvriBguTc4TveWF40hfg8="
	d := New("testing")
	payload := d.Sign(message)
	if payload != expected {
		t.Errorf("expected %s, got %s", expected, payload)
	}

}

func TestDangerous_Verify(t *testing.T) {
	payload := "aGVsbG8gd29ybGQulTKLm6tvriBguTc4TveWF40hfg8="

	expected := "hello world"
	d := New("testing")
	message, err := d.Verify(payload)

	if err != nil {
		t.Errorf("expected err=nil, got err=%s", err)
	}

	if message != expected {
		t.Errorf("expected %s, got %s", expected, message)
	}
}

func TestDangerous_DurationSignVerify(t *testing.T) {
	expected := "hello world"

	d := New("testing")
	d.Duration = 1 * time.Minute

	payload := d.Sign(expected)

	message, err := d.Verify(payload)
	if err != nil {
		t.Errorf("expected err=nil, got err=%s", err)
	}

	if message != expected {
		t.Errorf("expected %s, got %s", expected, message)
	}
}

func TestDangerous_TamperedData(t *testing.T) {
	payload := "aGVsbG8gd29ybGQulTKLm6tvriBguTc4TveWF40hfg=="

	expected := ""
	d := New("testing")
	message, err := d.Verify(payload)

	if err != ErrInvalidSignature {
		t.Errorf("expected err=invalid signature, got err=%s", err)
	}

	if message != expected {
		t.Errorf("expected %s, got %s", expected, message)
	}
}

func TestDangerous_Expired(t *testing.T) {
	expected := ""

	d := New("testing")
	d.Duration = -1 * time.Minute

	payload := d.Sign("hello world")

	message, err := d.Verify(payload)
	if err != ErrExpired {
		t.Errorf("expected err=expired, got err=%s", err)
	}

	if message != expected {
		t.Errorf("expected %s, got %s", expected, message)
	}
}
