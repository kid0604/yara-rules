import "pe"

rule HKTL_NET_GUID_SharpDomainSpray_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpDomainSpray"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii wide
		$typelibguid0up = "76FFA92B-429B-4865-970D-4E7678AC34EA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
