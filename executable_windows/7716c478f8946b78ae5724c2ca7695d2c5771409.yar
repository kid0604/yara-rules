import "pe"

rule HKTL_NET_GUID_Quasar_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/quasar/Quasar"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii wide
		$typelibguid0up = "CFDA6D2E-8AB3-4349-B89A-33E1F0DAB32B" ascii wide
		$typelibguid1lo = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii wide
		$typelibguid1up = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
