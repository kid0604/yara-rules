rule blackpos_v2
{
	meta:
		author = "@patrickrolsen"
		version = "0.1"
		reference = "http://blog.nuix.com/2014/09/08/blackpos-v2-new-variant-or-different-family"
		description = "Yara rule for detecting BlackPOS v2 malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage: -[start|stop|install|uninstall"
		$s2 = "\\SYSTEM32\\sc.exe config LanmanWorkstation"
		$s3 = "t.bat"
		$s4 = "mcfmisvc"

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
