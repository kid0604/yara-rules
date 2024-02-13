rule malware_spider_phpwebshell
{
	meta:
		description = "Spider PHP Shell"
		author = "JPCERT/CC Incident Response Group"
		hash = "ae17d97d8f7fd5216776e2ec457a2d60567bc6cc175206d0641861f71a7e7614"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<title> Spider PHP Shell" ascii
		$s2 = "<li><a href=\"?s=k\" id=\"t_10\" onclick=\"switchTab('t_10')\" target=\"main\"> Linux" ascii
		$s3 = "if($_COOKIE['admin_spiderpass'] != md5($password))" ascii
		$s4 = "case \"b\" : Guama_b(); break;" ascii

	condition:
		2 of them
}
