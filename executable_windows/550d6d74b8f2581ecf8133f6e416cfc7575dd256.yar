import "pe"

rule HKTL_NET_GUID_memscan_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nccgroup/memscan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "79462f87-8418-4834-9356-8c11e44ce189" ascii wide
		$typelibguid0up = "79462F87-8418-4834-9356-8C11E44CE189" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
