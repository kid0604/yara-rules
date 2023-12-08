import "pe"

rule MALWARE_Win_CoinMiner04
{
	meta:
		author = "ditekSHen"
		description = "Detects coinmining malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "createDll" fullword ascii
		$s2 = "getTasks" fullword ascii
		$s3 = "SetStartup" fullword ascii
		$s4 = "loadUrl" fullword ascii
		$s5 = "Processer" fullword ascii
		$s6 = "checkProcess" fullword ascii
		$s7 = "runProcess" fullword ascii
		$s8 = "createDir" fullword ascii
		$cnc1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" fullword wide
		$cnc2 = "?hwid=" fullword wide
		$cnc3 = "?timeout=1" fullword wide
		$cnc4 = "&completed=" fullword wide
		$cnc5 = "/cmd.php" wide

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) and 1 of ($cnc*))
}
