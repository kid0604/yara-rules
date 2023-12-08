private rule RTFFILE
{
	meta:
		description = "Detects RTF files"
		os = "windows,linux,macos"
		filetype = "document"

	condition:
		uint32be(0)==0x7B5C7274
}
