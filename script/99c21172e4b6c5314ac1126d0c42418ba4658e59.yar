rule HKTL_NET_GUID_GadgetToJScript
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/med0x2e/GadgetToJScript"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii nocase wide
		$typelibguid1 = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
