import "pe"

rule HKTL_NET_GUID_CSharpSetThreadContext_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii wide
		$typelibguid0up = "A1E28C8C-B3BD-44DE-85B9-8AA7C18A714D" ascii wide
		$typelibguid1lo = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii wide
		$typelibguid1up = "87C5970E-0C77-4182-AFE2-3FE96F785EBB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
