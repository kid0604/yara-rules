rule Windows_Hacktool_NetFilter_dd576d28
{
	meta:
		author = "Elastic Security"
		id = "dd576d28-b3e7-46b7-b19f-af37af434082"
		fingerprint = "b47477c371819a456ab24e158d6649e89b4d1756dc6da0b783b351d40b034fac"
		creation_date = "2022-04-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Hacktool.NetFilter"
		reference_sample = "88cfe6d7c81d0064045c4198d6ec7d3c50dc3ec8e36e053456ed1b50fc8c23bf"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.NetFilter"
		filetype = "executable"

	strings:
		$str1 = "\\NetProxyDriver.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
