rule portscanner
{
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}
