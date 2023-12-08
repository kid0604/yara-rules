rule APT30_Sample_21
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "d315daa61126616a79a8582145777d8a1565c615"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Service.dll" fullword ascii
		$s1 = "(%s:%s %s)" fullword ascii
		$s2 = "%s \"%s\",%s %s" fullword ascii
		$s5 = "Proxy-%s:%u" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
