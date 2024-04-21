rule bumblebee_13842_documents_lnk
{
	meta:
		description = "BumbleBee - file documents.lnk"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
		date = "2022-11-13"
		hash1 = "3c600328e1085dc73d672d068f3056e79e66bec7020be6ae907dd541201cd167"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
		$x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
		$x3 = "%windir%\\system32\\cmd.exe" fullword ascii
		$x4 = "Gcmd.exe" fullword wide
		$s5 = "desktop-30fdj39" fullword ascii

	condition:
		uint16(0)==0x004c and filesize <4KB and 1 of ($x*) and all of them
}
