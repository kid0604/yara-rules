rule HKTL_NET_GUID_Random_CSharpTools
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/xorrior/Random-CSharpTools"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii nocase wide
		$typelibguid1 = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii nocase wide
		$typelibguid2 = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii nocase wide
		$typelibguid3 = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii nocase wide
		$typelibguid4 = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii nocase wide
		$typelibguid5 = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii nocase wide
		$typelibguid6 = "60116613-c74e-41b9-b80e-35e02f25891e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
