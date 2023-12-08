rule Windows_VulnDriver_MsIo_ce0bda23
{
	meta:
		author = "Elastic Security"
		id = "ce0bda23-087c-49ec-b064-88b1d45e785a"
		fingerprint = "fe0c380dabec41458a5b5e0d7d38a4f9282f1ef87c51addd954da70d7c8ab1f2"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.MsIo"
		reference_sample = "43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability driver MsIo"
		filetype = "executable"

	strings:
		$str1 = "\\MsIo64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
