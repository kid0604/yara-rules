rule APT30_Sample_17
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "c3aa52ff1d19e8fc6704777caf7c5bd120056845"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Nkfvtyvn}]ty}ztU" fullword ascii
		$s4 = "IEXPL0RE" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
