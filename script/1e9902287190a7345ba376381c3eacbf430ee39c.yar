rule users_list
{
	meta:
		description = "Chinese Hacktool Set - file users_list.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
		$s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
		$s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii

	condition:
		filesize <12KB and all of them
}
