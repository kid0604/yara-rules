import "pe"

rule HKTL_NET_GUID_Crassus
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/vu-ls/Crassus"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-18"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "7e9729aa-4cf2-4d0a-8183-7fb7ce7a5b1a" ascii wide
		$typelibguid0up = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
