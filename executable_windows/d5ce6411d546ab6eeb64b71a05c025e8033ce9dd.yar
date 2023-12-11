import "pe"

rule HKTL_NET_GUID_CVE_2019_1064_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/RythmStick/CVE-2019-1064"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii wide
		$typelibguid0up = "FF97E98A-635E-4EA9-B2D0-1A13F6BDBC38" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
