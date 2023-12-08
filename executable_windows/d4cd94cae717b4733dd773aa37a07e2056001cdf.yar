rule Windows_VulnDriver_WinIo_c9cc6d00
{
	meta:
		author = "Elastic Security"
		id = "c9cc6d00-b1ed-4bab-b0f7-4f0d6c03bf08"
		fingerprint = "d9050466a2894b63ae86ec8888046efb49053edcc20287b9f17a4e6340a9cf92"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.WinIo"
		reference_sample = "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability driver WinIo"
		filetype = "executable"

	strings:
		$str1 = "\\WinioSys.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
