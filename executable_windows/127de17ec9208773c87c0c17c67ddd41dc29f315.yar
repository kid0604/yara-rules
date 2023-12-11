rule APT30_Sample_24
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "572caa09f2b600daa941c60db1fc410bef8d1771"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dizhi.gif" fullword ascii
		$s3 = "Mozilla/4.0" fullword ascii
		$s4 = "lyeagles" fullword ascii
		$s6 = "HHOSTR" ascii
		$s7 = "#MicrosoftHaveAck7" ascii
		$s8 = "iexplore." fullword ascii
		$s17 = "ModuleH" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
