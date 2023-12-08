import "pe"

rule HKTL_NET_GUID_Ladon_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/k8gege/Ladon"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii wide
		$typelibguid0up = "C335405F-5DF2-4C7D-9B53-D65ADFBED412" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
