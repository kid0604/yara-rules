rule tick_Datper
{
	meta:
		description = "detect Datper in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"
		hash = "4d4ad53fd47c2cc7338fab0de5bbba7cf45ee3d1d947a1942a93045317ed7b49"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { E8 03 00 00 }
		$b1 = "|||"
		$c1 = "Content-Type: application/x-www-form-urlencoded"
		$delphi = "SOFTWARE\\Borland\\Delphi\\" ascii wide
		$push7530h64 = { C7 C1 30 75 00 00 }
		$push7530h = { 68 30 75 00 00 }

	condition:
		$a1 and $b1 and $c1 and $delphi and ($push7530h64 or $push7530h)
}
