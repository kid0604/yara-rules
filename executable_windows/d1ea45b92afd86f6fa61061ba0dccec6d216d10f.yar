rule HKTL_NET_GUID_AsyncRAT_C_Sharp
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "619b7612-dfea-442a-a927-d997f99c497b" ascii nocase wide
		$typelibguid1 = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii nocase wide
		$typelibguid2 = "37e20baf-3577-4cd9-bb39-18675854e255" ascii nocase wide
		$typelibguid3 = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii nocase wide
		$typelibguid4 = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii nocase wide
		$typelibguid5 = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii nocase wide
		$typelibguid6 = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii nocase wide
		$typelibguid7 = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii nocase wide
		$typelibguid8 = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii nocase wide
		$typelibguid9 = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii nocase wide
		$typelibguid10 = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
