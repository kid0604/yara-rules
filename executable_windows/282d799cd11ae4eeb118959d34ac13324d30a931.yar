import "pe"

rule HKTL_NET_GUID_PSByPassCLM_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/padovah4ck/PSByPassCLM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "46034038-0113-4d75-81fd-eb3b483f2662" ascii wide
		$typelibguid0up = "46034038-0113-4D75-81FD-EB3B483F2662" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
