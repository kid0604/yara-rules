import "hash"

rule Network_Win7AMD64
{
	meta:
		author = "Jaume Martin"
		description = "Detects a specific file with MD5 hash eb92031a38f17d0e63285b5142b31966"
		os = "windows"
		filetype = "executable"

	condition:
		hash.md5(0, filesize )=="eb92031a38f17d0e63285b5142b31966"
}
