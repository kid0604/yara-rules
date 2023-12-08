rule thelast_index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cceff6dc247aaa25512bad22120a14b4"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"

	condition:
		all of them
}
