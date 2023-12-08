rule APT30_Sample_20
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "dizhi.gif" fullword ascii
		$s2 = "Mozilla/u" ascii
		$s3 = "XicrosoftHaveAck" ascii
		$s4 = "flyeagles" ascii
		$s10 = "iexplore." ascii
		$s13 = "WindowsGV" fullword ascii
		$s16 = "CatePipe" fullword ascii
		$s17 = "'QWERTY:/webpage3" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
