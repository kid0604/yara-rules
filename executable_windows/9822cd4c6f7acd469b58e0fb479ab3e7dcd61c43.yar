import "pe"

rule HKTL_NET_GUID_SharpFruit_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rvrsh3ll/SharpFruit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii wide
		$typelibguid0up = "3DA2F6DE-75BE-4C9D-8070-08DA45E79761" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
