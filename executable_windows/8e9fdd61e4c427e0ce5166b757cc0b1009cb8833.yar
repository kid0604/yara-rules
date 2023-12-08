import "pe"

rule HKTL_NET_GUID_MinerDropper_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DylanAlloy/MinerDropper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii wide
		$typelibguid0up = "46A7AF83-1DA7-40B2-9D86-6FD6223F6791" ascii wide
		$typelibguid1lo = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii wide
		$typelibguid1up = "8433A693-F39D-451B-955B-31C3E7FA6825" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
