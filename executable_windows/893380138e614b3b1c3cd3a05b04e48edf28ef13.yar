rule Windows_Hacktool_NetFilter_1cae6e26
{
	meta:
		author = "Elastic Security"
		id = "1cae6e26-b0ce-4f53-b88d-975b52ebcca7"
		fingerprint = "27003a6c9ad814e1ab2e7e284acfebdd18c9dd2af66eb9f44e5a9d59445fa086"
		creation_date = "2022-04-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Hacktool.NetFilter"
		reference_sample = "e2ec3b2a93c473d88bfdf2deb1969d15ab61737acc1ee8e08234bc5513ee87ea"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.NetFilter"
		filetype = "executable"

	strings:
		$str1 = "\\Driver_Map.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
