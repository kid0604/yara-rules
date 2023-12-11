import "pe"

rule Shamoon_Disttrack_Dropper
{
	meta:
		description = "Detects Shamoon 2.0 Disttrack Dropper"
		author = "Florian Roth"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 70
		hash1 = "4744df6ac02ff0a3f9ad0bf47b15854bbebb73c936dd02f7c79293a2828406f6"
		hash2 = "5a826b4fa10891cf63aae832fc645ce680a483b915c608ca26cedbb173b1b80a"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "\\#{9A6DB7D2-FECF-41ff-9A92-6EDA696613DF}#" wide
		$a2 = "\\#{8A6DB7D2-FECF-41ff-9A92-6EDA696613DE}#" wide
		$s1 = "\\amd64\\elrawdsk.pdb" fullword ascii
		$s2 = "RawDiskSample.exe" fullword wide
		$s3 = "RawDisk Driver. Allows write access to files and raw disk sectors for user mode applications in Windows 2000 and later." fullword wide
		$s4 = "elrawdsk.sys" fullword wide
		$s5 = "\\DosDevices\\ElRawDisk" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and 1 of ($a*) and 1 of ($s*))
}
