import "pe"

rule WaterBug_fa_malware_alt_1
{
	meta:
		description = "Symantec Waterbug Attack - FA malware variant"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku_Win32.sys\x00"
		$string4 = "rk_ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

	condition:
		($mz at 0) and ( any of ($string*))
}
