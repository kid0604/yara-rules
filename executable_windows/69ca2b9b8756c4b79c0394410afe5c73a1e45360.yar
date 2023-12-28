rule malware_TokyoX_Loader
{
	meta:
		description = "detect TokyoX Loader"
		author = "JPCERT/CC Incident Response Group"
		hash = "382b3d3bb1be4f14dbc1e82a34946a52795288867ed86c6c43e4f981729be4fc"
		os = "windows"
		filetype = "executable"

	strings:
		$str = "NtAllocateVirtuaNtWriteVirtualMeNtCreateThreadEx"

	condition:
		( uint16(0)==0x5A4D) and all of them
}
