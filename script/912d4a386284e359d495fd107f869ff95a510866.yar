import "pe"

rule HKTL_NET_GUID_AggressorScripts_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/harleyQu1nn/AggressorScripts"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0lo = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii wide
		$typelibguid0up = "AFD1FF09-2632-4087-A30C-43591F32E4E8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
