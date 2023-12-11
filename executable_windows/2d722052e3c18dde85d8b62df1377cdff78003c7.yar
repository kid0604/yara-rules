rule UACElevator
{
	meta:
		description = "UACElevator bypassing UAC - file UACElevator.exe"
		author = "Florian Roth"
		reference = "https://github.com/MalwareTech/UACElevator"
		date = "2015-05-14"
		hash = "fd29d5a72d7a85b7e9565ed92b4d7a3884defba6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\UACElevator.pdb" ascii
		$s1 = "%userprofile%\\Downloads\\dwmapi.dll" fullword ascii
		$s2 = "%windir%\\system32\\dwmapi.dll" fullword ascii
		$s3 = "Infection module: %s" fullword ascii
		$s4 = "Could not save module to %s" fullword ascii
		$s5 = "%s%s%p%s%ld%s%d%s" fullword ascii
		$s6 = "Stack area around _alloca memory reserved by this function is corrupted" fullword ascii
		$s7 = "Stack around the variable '" fullword ascii
		$s8 = "MSVCR120D.dll" fullword wide
		$s9 = "Address: 0x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <172KB and ($x1 or 8 of ($s*))
}
