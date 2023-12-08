import "pe"

rule apt_hellsing_implantstrings
{
	meta:
		Author = "Costin Raiu, Kaspersky Lab"
		Date = "2015-04-07"
		Description = "detection for Hellsing implants"
		Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"
		description = "Detection for Hellsing implants"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "the file uploaded failed !"
		$a2 = "ping 127.0.0.1"
		$b1 = "the file downloaded failed !"
		$b2 = "common.asp"
		$c = "xweber_server.exe"
		$d = "action="
		$debugpath1 = "d:\\Hellsing\\release\\msger\\" nocase
		$debugpath2 = "d:\\hellsing\\sys\\xrat\\" nocase
		$debugpath3 = "D:\\Hellsing\\release\\exe\\" nocase
		$debugpath4 = "d:\\hellsing\\sys\\xkat\\" nocase
		$debugpath5 = "e:\\Hellsing\\release\\clare" nocase
		$debugpath6 = "e:\\Hellsing\\release\\irene\\" nocase
		$debugpath7 = "d:\\hellsing\\sys\\irene\\" nocase
		$e = "msger_server.dll"
		$f = "ServiceMain"

	condition:
		($mz at 0) and ( all of ($a*)) or ( all of ($b*)) or ($c and $d) or ( any of ($debugpath*)) or ($e and $f) and filesize <500000
}
