import "pe"

rule WannaCry_Ransomware_Dropper
{
	meta:
		description = "WannaCry Ransomware Dropper"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
		date = "2017-05-12"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe /c \"%s\"" fullword ascii
		$s2 = "tasksche.exe" fullword ascii
		$s3 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
		$s4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4MB and all of them
}
