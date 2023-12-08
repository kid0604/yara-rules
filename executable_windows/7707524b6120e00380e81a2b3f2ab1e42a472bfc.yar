import "hash"

rule msvcrt_WIN8AMD64
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific file with MD5 hash 33c59fcdf027470e0ab1d366f54a6ebf"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="33c59fcdf027470e0ab1d366f54a6ebf"
}
