rule TeleBots_KillDisk_1
{
	meta:
		description = "Detects TeleBots malware - KillDisk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "8246f709efa922a485e1ca32d8b0d10dc752618e8b3fce4d3dd58d10e4a6a16d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Plug-And-Play Support Service" fullword wide
		$s2 = " /c \"echo Y|" fullword wide
		$s3 = "-set=06.12.2016#09:30 -est=1410" fullword ascii
		$s4 = "%d.%d.%d#%d:%d" fullword ascii
		$s5 = " /T /C /G " fullword wide
		$s6 = "[-] > %ls" fullword wide
		$s7 = "[+] > %ls" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 4 of them ) or (6 of them )
}
