rule dat_xpf
{
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" fullword wide
		$s3 = "\\DosDevices\\XScanPF" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
