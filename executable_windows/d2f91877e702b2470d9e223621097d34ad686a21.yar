rule APT30_Sample_26
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "e26588113417bf68cb0c479638c9cd99a48e846d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "forcegue" fullword ascii
		$s3 = "Windows\\Cur" fullword ascii
		$s4 = "System Id" fullword ascii
		$s5 = "Software\\Mic" fullword ascii
		$s6 = "utiBy0ToWideCh&$a" fullword ascii
		$s10 = "ModuleH" fullword ascii
		$s15 = "PeekNamed6G" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
