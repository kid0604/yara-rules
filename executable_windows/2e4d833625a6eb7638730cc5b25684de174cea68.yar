import "hash"

rule msvcrt_Win7AMD64
{
	meta:
		author = "Jaume Martin"
		description = "Detects the presence of a specific MD5 hash in the msvcrt file on Windows 7 64-bit systems"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="c8fc794cc5a22b5a1e0803b0b8acce77"
}
