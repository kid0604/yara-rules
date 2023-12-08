rule webshell_PHPRemoteView
{
	meta:
		description = "Web Shell - file PHPRemoteView.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "29420106d9a81553ef0d1ca72b9934d9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"

	condition:
		1 of them
}
