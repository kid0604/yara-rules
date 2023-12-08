import "pe"

rule apt_hellsing_msgertype2
{
	meta:
		Author = "Costin Raiu, Kaspersky Lab"
		Date = "2015-04-07"
		Description = "detection for Hellsing msger type 2 implants"
		Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"
		description = "Detection for Hellsing msger type 2 implants"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$a1 = "%s\\system\\%d.txt"
		$a2 = "_msger"
		$a3 = "http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4 = "http://%s/data/%s.1000001000"
		$a5 = "/lib/common.asp?action=user_upload&file="
		$a6 = "%02X-%02X-%02X-%02X-%02X-%02X"

	condition:
		($mz at 0) and (4 of ($a*)) and filesize <500000
}
