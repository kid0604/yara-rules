rule Windows_Hacktool_NetFilter_e8243dae
{
	meta:
		author = "Elastic Security"
		id = "e8243dae-33d9-4b54-8f4a-ba5cf5241767"
		fingerprint = "1542c32471f5d3f20beeb60c696085548d675f5d1cab1a0ef85a7060b01f0349"
		creation_date = "2022-04-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Hacktool.NetFilter"
		reference_sample = "760be95d4c04b10df89a78414facf91c0961020e80561eee6e2cb94b43b76510"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.NetFilter"
		filetype = "executable"

	strings:
		$str1 = "[NetFlt]:CTRL NDIS ModifyARP"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
