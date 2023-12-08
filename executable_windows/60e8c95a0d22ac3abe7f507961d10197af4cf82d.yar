rule Windows_VulnDriver_Biostar_d6cc23af
{
	meta:
		author = "Elastic Security"
		id = "d6cc23af-4502-4b18-bd10-17495e6e1443"
		fingerprint = "65a66dc00e62f32fd088809f3c88ceb9d59d264ecff0d9f830c35dfa464baf43"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: BS_HWMIO64_W10.sys, Version: 10.0.1806.2200"
		threat_name = "Windows.VulnDriver.Biostar"
		reference_sample = "1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 48 00 57 00 4D 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x98][\x00-\x08]|[\x00-\xff][\x00-\x07])([\x00-\x0e][\x00-\x07]|[\x00-\xff][\x00-\x06])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0d][\x00-\x07]|[\x00-\xff][\x00-\x06]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}
