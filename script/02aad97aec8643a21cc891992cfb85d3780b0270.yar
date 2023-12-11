rule EXPL_Log4j_CallBackDomain_IOCs_Dec21_1
{
	meta:
		description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
		date = "2021-12-12"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$xr1 = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/

	condition:
		1 of them
}
