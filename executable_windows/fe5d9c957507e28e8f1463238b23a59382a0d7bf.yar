rule HKTL_NET_GUID_Xploit
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/shargon/Xploit"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii nocase wide
		$typelibguid1 = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii nocase wide
		$typelibguid2 = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii nocase wide
		$typelibguid3 = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii nocase wide
		$typelibguid4 = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii nocase wide
		$typelibguid5 = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii nocase wide
		$typelibguid6 = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii nocase wide
		$typelibguid7 = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii nocase wide
		$typelibguid8 = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii nocase wide
		$typelibguid9 = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii nocase wide
		$typelibguid10 = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
