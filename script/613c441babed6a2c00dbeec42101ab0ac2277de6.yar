rule APT_Project_Sauron_basex_module
{
	meta:
		description = "Detects strings from basex module - Project Sauron report by Kaspersky"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "64, 64url, 32, 32url or 16."
		$s2 = "Force decoding when input is invalid/corrupt"
		$s3 = "This cruft"

	condition:
		$x1 or 2 of them
}
