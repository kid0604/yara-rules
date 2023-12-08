rule PasswordReminder
{
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."

	condition:
		all of them
}
