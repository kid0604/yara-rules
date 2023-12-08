rule HKTL_NET_GUID_k8fly
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/zzwlpx/k8fly"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
