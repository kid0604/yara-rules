import "pe"

rule HKTL_NET_GUID_clr_meterpreter_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/OJ/clr-meterpreter"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii wide
		$typelibguid0up = "6840B249-1A0E-433B-BE79-A927696EA4B3" ascii wide
		$typelibguid1lo = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii wide
		$typelibguid1up = "67C09D37-AC18-4F15-8DD6-B5DA721C0DF6" ascii wide
		$typelibguid2lo = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii wide
		$typelibguid2up = "E05D0DEB-D724-4448-8C4C-53D6A8E670F3" ascii wide
		$typelibguid3lo = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii wide
		$typelibguid3up = "C3CC72BF-62A2-4034-AF66-E66DA73E425D" ascii wide
		$typelibguid4lo = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii wide
		$typelibguid4up = "7ACE3762-D8E1-4969-A5A0-DCAF7B18164E" ascii wide
		$typelibguid5lo = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii wide
		$typelibguid5up = "3296E4A3-94B5-4232-B423-44F4C7421CB3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
