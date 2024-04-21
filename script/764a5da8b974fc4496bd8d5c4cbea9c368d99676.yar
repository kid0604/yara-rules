rule miner_batch
{
	meta:
		description = "file kit.bat"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
		date = "2022/07/10"
		hash1 = "4905b7776810dc60e710af96a7e54420aaa15467ef5909b260d9a9bc46911186"
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "%~dps0" fullword ascii
		$a2 = "set app" fullword ascii
		$a3 = "cd /d \"%~dps0\"" fullword ascii
		$a4 = "set usr=jood" fullword ascii
		$s1 = "schtasks /run" fullword ascii
		$s2 = "schtasks /delete" fullword ascii
		$a5 = "if \"%1\"==\"-s\" (" fullword ascii

	condition:
		uint16(0)==0xfeff and filesize <1KB and 3 of ($a*) and 1 of ($s*)
}
