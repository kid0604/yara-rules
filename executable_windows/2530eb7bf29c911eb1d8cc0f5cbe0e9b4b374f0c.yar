import "pe"

rule HKTL_NET_GUID_WheresMyImplant_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xbadjuju/WheresMyImplant"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii wide
		$typelibguid0up = "CCA59E4E-CE4D-40FC-965F-34560330C7E6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
