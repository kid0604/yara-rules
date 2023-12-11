import "hash"

rule Network_Win7x86
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific MD5 hash on Windows 7 x86 systems"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="548889baed7768b828d9c2f373abd225"
}
