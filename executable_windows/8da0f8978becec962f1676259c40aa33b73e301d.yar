rule PrikormkaEarlyVersion_alt_1
{
	meta:
		description = "Detects early versions of Prikormka malware"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4D 5A }
		$str36 = "IntelRestore" ascii fullword
		$str37 = "Resent" wide fullword
		$str38 = "ocp8.1" wide fullword
		$str39 = "rsfvxd.dat" ascii fullword
		$str40 = "tsb386.dat" ascii fullword
		$str41 = "frmmlg.dat" ascii fullword
		$str42 = "smdhost.dll" ascii fullword
		$str43 = "KDLLCFX" wide fullword
		$str44 = "KDLLRUNDRV" wide fullword

	condition:
		($mz at 0) and (2 of ($str*))
}
