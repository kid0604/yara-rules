import "pe"

rule HKTL_NET_GUID_DotNetToJScript_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/DotNetToJScript"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0lo = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii wide
		$typelibguid0up = "7E3F231C-0D0B-4025-812C-0EF099404861" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
