import "hash"

rule Network_WinXPx86
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific MD5 hash on Windows XP x86 systems"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="877341a16d5d223435c43a9db7f721bc"
}
