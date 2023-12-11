rule Windows_VulnDriver_MsIo_aa20a3c6
{
	meta:
		author = "Elastic Security"
		id = "aa20a3c6-c07c-49ef-be33-b61e612be42a"
		fingerprint = "28136b3928fa2c13dc3950df4b71f01f0d2e3977ca131df425096ec36fe6aad1"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.MsIo"
		reference_sample = "2270a8144dabaf159c2888519b11b61e5e13acdaa997820c09798137bded3dd6"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in MsIo driver"
		filetype = "executable"

	strings:
		$str1 = "\\MsIo32.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
