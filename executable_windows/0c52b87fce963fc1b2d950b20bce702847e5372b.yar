rule HKTL_NET_GUID_TikiTorch
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/TikiTorch"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii nocase wide
		$typelibguid1 = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii nocase wide
		$typelibguid2 = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii nocase wide
		$typelibguid3 = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii nocase wide
		$typelibguid4 = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii nocase wide
		$typelibguid5 = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii nocase wide
		$typelibguid6 = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
