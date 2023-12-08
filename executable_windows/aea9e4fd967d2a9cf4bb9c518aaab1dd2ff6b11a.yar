import "pe"

rule Equation_Kaspersky_HDD_reprogramming_module
{
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$s0 = "nls_933w.dll" fullword ascii
		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii

	condition:
		($mz at 0) and filesize <300000 and all of ($s*)
}
