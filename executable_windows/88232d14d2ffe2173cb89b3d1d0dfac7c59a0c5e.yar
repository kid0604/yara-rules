rule APT30_Sample_35
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
		$s5 = "Startup>A" fullword ascii
		$s18 = "olhelp32Snapshot" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
