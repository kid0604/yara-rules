rule APT30_Sample_30
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "3b684fa40b4f096e99fbf535962c7da5cf0b4528"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
		$s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
		$s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
		$s5 = "ZRLDownloadToFileA" fullword ascii
		$s9 = "5.1.2600.2180" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
