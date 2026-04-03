package runtime

import (
	"testing"
)

func TestPathToPackage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "libssl"},
		{"/usr/lib/libcrypto.so.1.1", "libcrypto"},
		{"/lib/x86_64-linux-gnu/libc.so.6", "libc"},
		{"/usr/lib/python3.11/site-packages/flask/app.py", "flask"},
		{"/usr/lib/python3.11/site-packages/requests/__init__.py", "requests"},
		{"/app/node_modules/express/index.js", "express"},
		{"/app/node_modules/@types/node/index.js", "@types/node"},
		{"/usr/share/java/log4j-core-2.17.1.jar", "log4j-core"},
		{"/opt/app/spring-boot-starter-3.2.0.jar", "spring-boot-starter"},
		{"/usr/lib/ruby/gems/3.1.0/gems/nokogiri-1.15.4/lib/nokogiri.rb", "nokogiri"},
		{"/some/random/file.txt", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := pathToPackage(tt.path)
		if got != tt.want {
			t.Errorf("pathToPackage(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestIsRuntimeFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/lib/libssl.so.3", true},
		{"/app/lib.jar", true},
		{"/usr/lib/python3.11/site-packages/flask/app.py", true},
		{"/app/node_modules/express/index.js", true},
		{"/usr/lib/ruby/gems/3.1.0/gems/nokogiri/lib.rb", true},
		{"/etc/passwd", false},
		{"/var/log/syslog", false},
		{"/proc/1/maps", false},
	}

	for _, tt := range tests {
		got := isRuntimeFile(tt.path)
		if got != tt.want {
			t.Errorf("isRuntimeFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestMapKeys(t *testing.T) {
	m := map[string]bool{"a": true, "b": true, "c": true}
	keys := mapKeys(m)
	if len(keys) != 3 {
		t.Errorf("mapKeys returned %d keys, want 3", len(keys))
	}
}
