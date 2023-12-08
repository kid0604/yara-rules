import "pe"

rule HKTL_NET_GUID_SharpSpray_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii wide
		$typelibguid0up = "51C6E016-1428-441D-82E9-BB0EB599BBC8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
