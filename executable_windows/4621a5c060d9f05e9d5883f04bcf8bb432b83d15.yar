import "pe"

rule APT_APT41_POISONPLUG_3
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		date = "2019-08-07"
		score = 80
		hash1 = "70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Rundll32.exe \"%s\", DisPlay 64" fullword ascii
		$s2 = "tcpview.exe" fullword ascii
		$s3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword ascii
		$s4 = "AxEeulaVteSgeR" fullword ascii
		$s5 = "%04d-%02d-%02d_%02d-%02d-%02d.dmp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 3 of them
}
