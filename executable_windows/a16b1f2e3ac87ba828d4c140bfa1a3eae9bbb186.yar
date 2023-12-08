import "hash"

rule msvcrt_Win7x86
{
	meta:
		author = "Jaume Martin"
		description = "Yara rule to detect a specific version of msvcrt on Windows 7 x86"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="7713e5c5a48b020c9575b1b50f2e5e9e"
}
