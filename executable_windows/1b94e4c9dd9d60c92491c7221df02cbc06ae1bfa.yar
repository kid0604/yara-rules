import "pe"

rule HKTL_NET_GUID_SharpCradle_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/anthemtotheego/SharpCradle"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii wide
		$typelibguid0up = "F70D2B71-4AAE-4B24-9DAE-55BC819C78BB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
