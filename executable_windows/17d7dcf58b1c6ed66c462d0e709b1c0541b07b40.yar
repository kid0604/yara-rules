rule HKTL_NET_GUID_njCrypter
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/0xPh0enix/njCrypter"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii nocase wide
		$typelibguid1 = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
