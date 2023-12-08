rule ZLoader
{
	meta:
		id = "2JUpH4J7F9VVLnQm59k5t9"
		fingerprint = "b6cc36932d196457ad66df7815f1eb3a5e8561686d9184286a375bc78a209db0"
		version = "1.0"
		creation_date = "2020-04-01"
		first_imported = "2021-12-30"
		last_modified = "2022-02-03"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies ZLoader in memory or unpacked."
		category = "MALWARE"
		malware = "ZLOADER"
		malware_type = "LOADER"
		os = "windows"
		filetype = "executable"

	strings:
		$code = { 89 f8 8b 0d ?? ?? ?? ?? 99 f7 7? ?? 8b 4? ?? 0f b6 1c ?? 32
    1c 38 88 1c 3e 8d 7f 01 74 ?? e8 ?? ?? ?? ?? 80 fb 7f 74 ?? 38 c3 7d
    ?? 80 fb 0d 77 ?? 0f b6 c3 b9 00 26 00 00 0f a3 c1 72 ?? }
		$dll = "antiemule-loader-bot32.dll" ascii wide fullword
		$s1 = "/post.php" ascii wide
		$s2 = "BOT-INFO" ascii wide
		$s3 = "Connection: close" ascii wide
		$s4 = "It's a debug version." ascii wide
		$s5 = "Proxifier is a conflict program, form-grabber and web-injects will not works. Terminate proxifier for solve this problem." ascii wide
		$s6 = "rhnbeqcuwzbsjwfsynex" ascii wide fullword

	condition:
		$code or $dll or (4 of ($s*))
}
