import "pe"

rule Havex_Trojan_PHP_Server
{
	meta:
		Author = "Florian Roth"
		Date = "2014/06/24"
		Description = "Detects the PHP server component of the Havex RAT"
		Reference = "www.f-secure.com/weblog/archives/00002718.html"
		description = "Detects the PHP server component of the Havex RAT"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "havex--></body></head>"
		$s2 = "ANSWERTAG_START"
		$s3 = "PATH_BLOCKFILE"

	condition:
		all of them
}
