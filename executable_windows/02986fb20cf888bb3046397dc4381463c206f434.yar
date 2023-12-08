rule Windows_VulnDriver_Asrock_cdf192f9
{
	meta:
		author = "Elastic Security"
		id = "cdf192f9-c62f-4e00-b6a9-df85d10fee99"
		fingerprint = "f27c61c67b51ab88994742849dcd1311064ef0cacddb57503336d08f45059060"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.Asrock"
		reference_sample = "2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in Asrock drivers"
		filetype = "executable"

	strings:
		$str1 = "\\AsrDrv103.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
