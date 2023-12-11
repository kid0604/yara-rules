import "hash"

rule Gandcrab_hash
{
	meta:
		description = "Detect the risk of GandCrab Rule 5"
		os = "windows"
		filetype = "executable"

	condition:
		hash.sha256(0, filesize )=="eb9207371e53414cfcb2094a2e34bd68be1a9eedbe49c4ded82b2adb8fa1d23d"
}
