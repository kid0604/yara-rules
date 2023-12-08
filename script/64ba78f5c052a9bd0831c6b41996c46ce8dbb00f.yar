rule CN_Honker_PHP_php11
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file php11.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dcc8226e7eb20e4d4bef9e263c14460a7ee5e030"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<tr><td><b><?php if (!$win) {echo wordwrap(myshellexec('id'),90,'<br>',1);} else" ascii
		$s2 = "foreach (glob($_GET['pathtomass'].\"/*.htm\") as $injectj00) {" fullword ascii
		$s3 = "echo '[cPanel Found] '.$login.':'.$pass.\"  Success\\n\";" fullword ascii

	condition:
		filesize <800KB and all of them
}
