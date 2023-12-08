rule HKTL_NET_GUID_KeeThief
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/GhostPack/KeeThief"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid1 = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii nocase wide
		$typelibguid3 = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii nocase wide
		$typelibguid4 = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii nocase wide
		$typelibguid5 = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii nocase wide
		$typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide
		$typelibguid7 = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
