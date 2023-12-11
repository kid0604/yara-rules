rule Windows_VulnDriver_Rtkio_13b3c88b
{
	meta:
		author = "Elastic Security"
		id = "13b3c88b-daa7-4402-ad31-6fc7d4064087"
		fingerprint = "3788e6a7a759796a2675116e4d291324f97114773cf53345f15796566266f702"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: rtkio.sys"
		threat_name = "Windows.VulnDriver.Rtkio"
		reference_sample = "478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}
