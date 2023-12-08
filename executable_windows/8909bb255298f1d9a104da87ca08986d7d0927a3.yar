import "pe"

rule malware_apt15_royalcli_2
{
	meta:
		author = "Nikolaos Pantazopoulos"
		description = "APT15 RoyalCli backdoor"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "%shkcmd.exe" fullword
		$string2 = "myRObject" fullword
		$string3 = "%snewcmd.exe" fullword
		$string4 = "%s~clitemp%08x.tmp" fullword
		$string6 = "myWObject" fullword

	condition:
		uint16(0)==0x5A4D and 2 of them
}
