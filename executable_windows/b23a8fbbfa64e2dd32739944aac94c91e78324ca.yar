rule HKTL_NET_GUID_SyscallPOC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SolomonSklash/SyscallPOC"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii nocase wide
		$typelibguid1 = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
