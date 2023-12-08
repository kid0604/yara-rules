import "hash"

rule msvcrt_WinXPx86
{
	meta:
		author = "Jaume Martin"
		description = "Detects the presence of a specific version of msvcrt.dll on Windows XP x86"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="b68f72d77754f8b76168ced0924a4174"
}
