import "pe"

rule HKTL_NET_GUID_SharpCompile_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SpiderLabs/SharpCompile"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii wide
		$typelibguid0up = "63F81B73-FF18-4A36-B095-FDCB4776DA4C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
