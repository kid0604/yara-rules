import "pe"

rule HKTL_NET_GUID_nopowershell_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/bitsadmin/nopowershell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii wide
		$typelibguid0up = "555AD0AC-1FDB-4016-8257-170A74CB2F55" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
