import "pe"

rule HKTL_NET_GUID_Salsa_tools_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hackplayers/Salsa-tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "276004bb-5200-4381-843c-934e4c385b66" ascii wide
		$typelibguid0up = "276004BB-5200-4381-843C-934E4C385B66" ascii wide
		$typelibguid1lo = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii wide
		$typelibguid1up = "CFCBF7B6-1C69-4B1F-8651-6BDB4B55F6B9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
