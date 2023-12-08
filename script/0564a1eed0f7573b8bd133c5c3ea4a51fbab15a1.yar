rule CN_Honker_Webshell__php1_php7_php9
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "c2f4b150f53c78777928921b3a985ec678bfae32"
		hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii
		$s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
		$s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii

	condition:
		filesize <300KB and all of them
}
