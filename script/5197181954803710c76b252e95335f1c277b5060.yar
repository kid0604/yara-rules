rule CN_Honker_Webshell_WebShell
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
		$s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii
		$s3 = "warn \"command: '$command'\\n\";" fullword ascii

	condition:
		filesize <30KB and 2 of them
}
