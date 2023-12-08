rule eBayId_index3
{
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0412b1e37f41ea0d002e4ed11608905f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"

	condition:
		all of them
}
