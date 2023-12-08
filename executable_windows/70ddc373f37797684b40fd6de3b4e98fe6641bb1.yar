rule CN_Honker_Xiaokui_conversion_tool
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Xiaokui_conversion_tool.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dccd163e94a774b01f90c1e79f186894e2f27de3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "update [dv_user] set usergroupid=1 where userid=2;--" fullword ascii
		$s2 = "To.exe" fullword wide
		$s3 = "by zj1244" ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 2 of them
}
