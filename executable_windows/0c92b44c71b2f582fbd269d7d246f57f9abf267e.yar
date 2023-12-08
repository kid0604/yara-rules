import "pe"

rule HKTL_NET_GUID_SharpLdapRelayScan
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/klezVirus/SharpLdapRelayScan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-03-15"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a93ee706-a71c-4cc1-bf37-f26c27825b68" ascii wide
		$typelibguid0up = "A93EE706-A71C-4CC1-BF37-F26C27825B68" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
