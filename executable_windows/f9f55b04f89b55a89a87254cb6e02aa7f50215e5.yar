rule HKTL_NET_GUID_clr_meterpreter
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/OJ/clr-meterpreter"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii nocase wide
		$typelibguid1 = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii nocase wide
		$typelibguid2 = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii nocase wide
		$typelibguid3 = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii nocase wide
		$typelibguid4 = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii nocase wide
		$typelibguid5 = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
