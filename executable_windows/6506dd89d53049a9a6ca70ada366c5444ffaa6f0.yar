rule case_5087_7A86
{
	meta:
		description = "Files - file 7A86.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-30"
		hash1 = "9d63a34f83588e208cbd877ba4934d411d5273f64c98a43e56f8e7a45078275d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ibrndbiclw.dll" fullword ascii
		$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s3 = "Type Descriptor'" fullword ascii
		$s4 = "operator co_await" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
