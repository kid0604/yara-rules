private rule PotaoDecoy
{
	meta:
		description = "Detects PotaoDecoy malware based on specific strings and patterns"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$str1 = "eroqw11"
		$str2 = "2sfsdf"
		$str3 = "RtlDecompressBuffer"
		$wiki_str = "spanned more than 100 years and ruined three consecutive" wide
		$old_ver1 = {53 68 65 6C 6C 33 32 2E 64 6C 6C 00 64 61 66 73 72 00 00 00 64 61 66 73 72 00 00 00 64 6F 63 (00 | 78)}
		$old_ver2 = {6F 70 65 6E 00 00 00 00 64 6F 63 00 64 61 66 73 72 00 00 00 53 68 65 6C 6C 33 32 2E 64 6C 6C 00}

	condition:
		($mz at 0) and (( all of ($str*)) or any of ($old_ver*) or $wiki_str)
}
