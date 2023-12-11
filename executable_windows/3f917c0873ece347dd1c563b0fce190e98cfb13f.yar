rule HKTL_NET_GUID_SweetPotato
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/CCob/SweetPotato"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii nocase wide
		$typelibguid1 = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
