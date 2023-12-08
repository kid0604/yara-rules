import "pe"

rule HvS_APT37_smb_scanner
{
	meta:
		description = "Unknown smb login scanner used by APT37"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Marc Stroebel"
		date = "2020-12-15"
		reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		reference2 = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
		$s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
		$s3 = "Load mpr.dll Error " fullword ascii
		$s4 = "Load Netapi32.dll Error " fullword ascii
		$s5 = "%s U/P not Correct! - %d" fullword ascii
		$s6 = "GetNetWorkInfo Version 1.0" fullword wide
		$s7 = "Hello World!" fullword wide
		$s8 = "%s Error: %ld" fullword ascii
		$s9 = "%s U/P Correct!" fullword ascii
		$s10 = "%s --------" fullword ascii
		$s11 = "%s%-30s%I64d" fullword ascii
		$s12 = "%s%-30s(DIR)" fullword ascii
		$s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
		$s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
		$s15 = "Share:              Type:                   Remark:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (10 of them )
}
