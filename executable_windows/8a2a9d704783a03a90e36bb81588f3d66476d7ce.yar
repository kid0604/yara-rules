rule HKTL_NET_GUID_OffensiveCSharp
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/diljith369/OffensiveCSharp"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii nocase wide
		$typelibguid1 = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii nocase wide
		$typelibguid2 = "512015de-a70f-4887-8eae-e500fd2898ab" ascii nocase wide
		$typelibguid3 = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii nocase wide
		$typelibguid4 = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii nocase wide
		$typelibguid5 = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii nocase wide
		$typelibguid6 = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii nocase wide
		$typelibguid7 = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii nocase wide
		$typelibguid8 = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii nocase wide
		$typelibguid9 = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii nocase wide
		$typelibguid10 = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii nocase wide
		$typelibguid11 = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
