import "pe"

rule HKTL_NET_GUID_HiveJack_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Viralmaniar/HiveJack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii wide
		$typelibguid0up = "E12E62FE-BEA3-4989-BF04-6F76028623E3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
