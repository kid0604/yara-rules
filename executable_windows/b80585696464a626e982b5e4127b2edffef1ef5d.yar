rule WaterBug_fa_malware
{
	meta:
		description = "Symantec Waterbug Attack - FA malware variant"
		author = "Symantec Security Response"
		date = "2015-01-22"
		modified = "2023-01-27"
		reference = "http://t.co/rF35OaAXrl"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku_Win32.sys\x00"
		$string4 = "rk_ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

	condition:
		uint16(0)==0x5A4D and ( any of ($string*))
}
