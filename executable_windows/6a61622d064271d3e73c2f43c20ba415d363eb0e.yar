import "hash"

rule MemStub64_GH1
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific MD5 hash value associated with a memory dumping tool"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="2350403a09e6928f0a7ba5d74da58cb9"
}
