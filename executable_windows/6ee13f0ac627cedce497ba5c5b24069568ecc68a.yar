import "hash"

rule msvcrt_WIN8x86
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific MD5 hash associated with the msvcrt library on Windows 8 x86"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="95490c2b284a9bb63f0ee49254ab727e"
}
