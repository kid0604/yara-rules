rule APT30_Sample_18
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "355436a16d7a2eba8a284b63bb252a8bb1644751"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "w.km-nyc.com" fullword ascii
		$s1 = "tscv.exe" fullword ascii
		$s2 = "Exit/app.htm" ascii
		$s3 = "UBD:\\D" ascii
		$s4 = "LastError" ascii
		$s5 = "MicrosoftHaveAck" ascii
		$s7 = "HHOSTR" ascii
		$s20 = "XPL0RE." ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
