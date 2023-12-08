import "pe"

rule Turla_APT_Malware_Gen3
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash2 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash3 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash4 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash5 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash6 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash7 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		hash8 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash9 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\\\.\\pipe\\sdlrpc" fullword ascii
		$x2 = "WaitMutex Abandoned %p" fullword ascii
		$x3 = "OPER|Wrong config: no port|" fullword ascii
		$x4 = "OPER|Wrong config: no lastconnect|" fullword ascii
		$x5 = "OPER|Wrong config: empty address|" fullword ascii
		$x6 = "Trans task %d obj %s ACTIVE fail robj %s" fullword ascii
		$x7 = "OPER|Wrong config: no auth|" fullword ascii
		$x8 = "OPER|Sniffer '%s' running... ooopppsss...|" fullword ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Post Platform" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Pre Platform" fullword ascii
		$s3 = "www.yahoo.com" fullword ascii
		$s4 = "MSXIML.DLL" fullword wide
		$s5 = "www.bing.com" fullword ascii
		$s6 = "%s: http://%s%s" fullword ascii
		$s7 = "/javascript/view.php" fullword ascii
		$s8 = "Task %d failed %s,%d" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE %d.0; " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or 6 of ($s*))) or (10 of them )
}
