import "pe"

rule HKTL_NET_GUID_logger_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/xxczaki/logger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii wide
		$typelibguid0up = "9E92A883-3C8B-4572-A73E-BB3E61CFDC16" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
