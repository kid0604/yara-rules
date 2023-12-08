rule APT30_Sample_14
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b0740175d20eab79a5d62cdbe0ee1a89212a8472"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "AdobeReader.exe" fullword wide
		$s4 = "10.1.7.27" fullword wide
		$s5 = "Copyright 1984-2012 Adobe Systems Incorporated and its licensors. All ri" wide
		$s8 = "Adobe Reader" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
