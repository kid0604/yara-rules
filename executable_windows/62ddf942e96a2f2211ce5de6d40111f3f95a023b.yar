rule possible_wwlib_hijacking
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "observed with campaigns such as APT32, this attempts to look for the archive files such as RAR."
		reference = "040abac56542a2e0f384adf37c8f95b2b6e6ce3a0ff969e3c1d572e6b4053ff3"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "/wwlib.dll"
		$neg1 = "This program cannot be run in DOS mode"
		$neg2 = "Doctor Web"
		$neg3 = "pandasecurity.com"

	condition:
		$a and not any of ($neg1,$neg2,$neg3)
}
