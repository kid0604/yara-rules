rule Equation_Kaspersky_HDD_reprogramming_module_alt_1
{
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "nls_933w.dll" fullword ascii
		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300000 and all of ($s*)
}
