rule win_redline_bytecodes_jan_2024
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes found in late 2023 Redline malware"
		sha_256 = "ea1271c032046d482ed94c6d2c2c6e3ede9bea57dff13156cabca42b24fb9332"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {00 00 7E ?? ?? ?? 04 7E ?? ?? ?? 04 28 ?? ?? ?? 06 17 8D ?? ?? ?? 01 25 16 1F 7C 9D 6F ?? ?? ?? 0A 13 ?? 16 13 ?? 38 }
		$s2 = "mscoree.dll" ascii

	condition:
		$s1 and $s2 and uint16(0)==0x5a4d
}
