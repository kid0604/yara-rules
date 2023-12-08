rule APT30_Sample_2
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "0359ffbef6a752ee1a54447b26e272f4a5a35167"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "ForZRLnkWordDlg.EXE" fullword wide
		$s1 = "ForZRLnkWordDlg Microsoft " fullword wide
		$s9 = "ForZRLnkWordDlg 1.0 " fullword wide
		$s11 = "ForZRLnkWordDlg" fullword wide
		$s12 = " (C) 2011" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
