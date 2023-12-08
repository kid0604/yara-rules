rule HKTL_NET_GUID_Sharp_Suite
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/Sharp-Suite"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii nocase wide
		$typelibguid1 = "5611236e-2557-45b8-be29-5d1f074d199e" ascii nocase wide
		$typelibguid2 = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii nocase wide
		$typelibguid3 = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii nocase wide
		$typelibguid4 = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii nocase wide
		$typelibguid5 = "a5f883ce-1f96-4456-bb35-40229191420c" ascii nocase wide
		$typelibguid6 = "28978103-d90d-4618-b22e-222727f40313" ascii nocase wide
		$typelibguid7 = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii nocase wide
		$typelibguid8 = "414187db-5feb-43e5-a383-caa48b5395f1" ascii nocase wide
		$typelibguid9 = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii nocase wide
		$typelibguid10 = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii nocase wide
		$typelibguid11 = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii nocase wide
		$typelibguid12 = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii nocase wide
		$typelibguid13 = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii nocase wide
		$typelibguid14 = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii nocase wide
		$typelibguid15 = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
