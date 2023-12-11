rule Pirpi_1609_A
{
	meta:
		description = "Detects Pirpi Backdoor - and other malware (generic rule)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "2a5a0bc350e774bd784fc25090518626b65a3ce10c7401f44a1616ea2ae32f4c"
		hash2 = "8caa179ec20b6e3938d17132980e0b9fe8ef753a70052f7e857b339427eb0f78"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "expand.exe1.gif" fullword ascii
		$c1 = "expand.exe" fullword ascii
		$c2 = "ctf.exe" fullword ascii
		$s1 = "flvUpdate.exe" fullword wide
		$s2 = "www.ThinkWorking.com" fullword wide
		$s3 = "ctfnon.exe" fullword ascii
		$s4 = "flv%d.exe" fullword ascii
		$s5 = "HARDWARE\\DESCRIPTION\\System\\BIOS" fullword ascii
		$s6 = "12811[%d].gif" fullword ascii
		$s7 = "GetApp03" fullword wide
		$s8 = "flvUpdate" fullword wide
		$s9 = "%d-%4.4d%d" fullword ascii
		$s10 = "http://%s/%5.5d.html" fullword ascii
		$s11 = "flvbho.exe" fullword wide
		$op1 = { 74 08 c1 cb 0d 03 da 40 eb }
		$op2 = { 03 f5 56 8b 76 20 03 f5 33 c9 49 }
		$op3 = { 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and ($x1 or all of ($c*) or all of ($op*))) or (8 of them )
}
