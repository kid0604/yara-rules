import "pe"

rule HKTL_NET_GUID_SQLRecon
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/skahwah/SQLRecon"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-01-20"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "612c7c82-d501-417a-b8db-73204fdfda06" ascii wide
		$typelibguid0up = "612C7C82-D501-417A-B8DB-73204FDFDA06" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
