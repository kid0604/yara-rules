rule case_5087_24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9
{
	meta:
		description = "Files - file 24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-30"
		hash1 = "24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fbtwmjnrrovmd.dll" fullword ascii
		$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s3 = " Type Descriptor'" fullword ascii
		$s4 = "operator co_await" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and all of them
}
