import "pe"

rule MALWARE_Win_DLInjector02
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader injector"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "In$J$ct0r" fullword wide
		$x2 = "%InJ%ector%" fullword wide
		$a1 = "WriteProcessMemory" fullword wide
		$a2 = "URLDownloadToFileA" fullword ascii
		$a3 = "Wow64SetThreadContext" fullword wide
		$a4 = "VirtualAllocEx" fullword wide
		$s1 = "RunPE" fullword wide
		$s2 = "SETTINGS" fullword wide
		$s3 = "net.pipe" fullword wide
		$s4 = "vsmacros" fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or ( all of ($a*) and 3 of ($s*)))
}
