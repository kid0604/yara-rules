rule Windows_VulnDriver_XTier_8a2f6dc1
{
	meta:
		author = "Elastic Security"
		id = "8a2f6dc1-82f4-4e87-a4d6-49a36ea4fab8"
		fingerprint = "0142537ba2fa5fa44cf89e0f2126da2b18894115c6152e1f3eaeb759951aba26"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: libnicm.sys, Version: 3.1.12.0"
		threat_name = "Windows.VulnDriver.XTier"
		reference_sample = "95d50c69cdbf10c9c9d61e64fe864ac91e6f6caa637d128eb20e1d3510e776d3"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6C 00 69 00 62 00 6E 00 69 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}
