import "pe"

rule MALWARE_Win_DLInjector05
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader / injector (NiceProcess)"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "pidhtmpfile.tmp" fullword ascii
		$s2 = "pidhtmpdata.tmp" fullword ascii
		$s3 = "pidHTSIG" fullword ascii
		$s4 = "Taskmgr.exe" fullword ascii
		$s5 = "[HP][" ascii
		$s6 = "[PP][" ascii
		$s7 = { 70 69 64 68 74 6d 70 66 69 6c 65 2e 74 6d 70 00
                2e 64 6c 6c 00 00 00 00 70 69 64 48 54 53 49 47
                00 00 00 00 ?? ?? 00 00 54 61 73 6b 6d 67 72 2e
                65 78 65 }

	condition:
		uint16(0)==0x5a4d and 4 of them
}
