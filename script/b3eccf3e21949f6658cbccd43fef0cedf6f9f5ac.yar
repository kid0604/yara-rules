rule CN_Honker_Webshell_PHP_php8
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b7b49f1d6645865691eccd025e140c521ff01cce"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii
		$s1 = "function startfile($path = 'dodo.zip')" fullword ascii
		$s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii
		$s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii

	condition:
		filesize <25KB and 2 of them
}
