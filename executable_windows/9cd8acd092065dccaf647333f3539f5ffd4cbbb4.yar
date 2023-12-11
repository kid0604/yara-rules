import "pe"

rule Equation_Kaspersky_DoubleFantasy_1
{
	meta:
		description = "Equation Group Malware - DoubleFantasy"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$z1 = "msvcp5%d.dll" fullword ascii
		$s0 = "actxprxy.GetProxyDllInfo" fullword ascii
		$s3 = "actxprxy.DllGetClassObject" fullword ascii
		$s5 = "actxprxy.DllRegisterServer" fullword ascii
		$s6 = "actxprxy.DllUnregisterServer" fullword ascii
		$x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
		$x2 = "191H1a1" fullword ascii
		$x3 = "November " fullword ascii
		$x4 = "abababababab" fullword ascii
		$x5 = "January " fullword ascii
		$x6 = "October " fullword ascii
		$x7 = "September " fullword ascii

	condition:
		($mz at 0) and filesize <350000 and (($z1) or ( all of ($s*) and 6 of ($x*)))
}
