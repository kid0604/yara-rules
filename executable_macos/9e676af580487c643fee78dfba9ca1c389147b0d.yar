rule hacktool_macos_keylogger_eldeveloper_keystats
{
	meta:
		description = "A simple keylogger for macOS."
		reference = "https://github.com/ElDeveloper/keystats"
		author = "@mimeframe"
		os = "macos"
		filetype = "executable"

	strings:
		$a1 = "YVBKeyLoggerPerishedNotification" wide ascii
		$a2 = "YVBKeyLoggerPerishedByLackOfResponseNotification" wide ascii
		$a3 = "YVBKeyLoggerPerishedByUserChangeNotification" wide ascii

	condition:
		2 of ($a*)
}
