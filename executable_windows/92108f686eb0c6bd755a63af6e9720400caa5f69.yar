rule HKTL_NET_GUID_StormKitty
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/StormKitty"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii nocase wide
		$typelibguid1 = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
