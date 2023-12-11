rule Windows_Hacktool_NetFilter_b4f2a520
{
	meta:
		author = "Elastic Security"
		id = "b4f2a520-88bf-447e-bbc4-5d8bfd2c9753"
		fingerprint = "1d8da6f78149e2db6b54faa381ce8eb285930226a5b4474e04937893c831809f"
		creation_date = "2022-04-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Hacktool.NetFilter"
		reference_sample = "5d0d5373c5e52c4405f4bd963413e6ef3490b7c4c919ec2d4e3fb92e91f397a0"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.NetFilter"
		filetype = "executable"

	strings:
		$str1 = "\\netfilterdrv.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
