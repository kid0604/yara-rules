private rule PrikormkaEarlyVersion
{
	meta:
		description = "Detects early version of Prikormka malware"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "IntelRestore" ascii fullword
		$str2 = "Resent" wide fullword
		$str3 = "ocp8.1" wide fullword
		$str4 = "rsfvxd.dat" ascii fullword
		$str5 = "tsb386.dat" ascii fullword
		$str6 = "frmmlg.dat" ascii fullword
		$str7 = "smdhost.dll" ascii fullword
		$str8 = "KDLLCFX" wide fullword
		$str9 = "KDLLRUNDRV" wide fullword

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
