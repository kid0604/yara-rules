rule CN_Honker_Webshell_ASP_shell
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b7b34215c2293ace70fc06cbb9ce73743e867289"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
		$s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
		$s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii

	condition:
		filesize <1KB and all of them
}
