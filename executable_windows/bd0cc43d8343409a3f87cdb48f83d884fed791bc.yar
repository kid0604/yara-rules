rule migrate_apc
{
	meta:
		author = "x0r"
		description = "APC queue tasks migration"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "OpenThread"
		$c2 = "QueueUserAPC"

	condition:
		all of them
}
