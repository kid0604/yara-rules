import "pe"

rule HKTL_NET_GUID_AMSI_Handler_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/AMSI_Handler"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii wide
		$typelibguid0up = "D829426C-986C-40A4-8EE2-58D14E090EF2" ascii wide
		$typelibguid1lo = "86652418-5605-43fd-98b5-859828b072be" ascii wide
		$typelibguid1up = "86652418-5605-43FD-98B5-859828B072BE" ascii wide
		$typelibguid2lo = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii wide
		$typelibguid2up = "1043649F-18E1-41C4-AE8D-AC4D9A86C2FC" ascii wide
		$typelibguid3lo = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii wide
		$typelibguid3up = "1D920B03-C537-4659-9A8C-09FB1D615E98" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
