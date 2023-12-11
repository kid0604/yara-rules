rule INDICATOR_RTF_RemoteTemplate
{
	meta:
		author = "ditekSHen"
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "{\\*\\template http" ascii nocase
		$s2 = "{\\*\\template file" ascii nocase
		$s3 = "{\\*\\template \\u-" ascii nocase

	condition:
		uint32(0)==0x74725c7b and 1 of them
}
