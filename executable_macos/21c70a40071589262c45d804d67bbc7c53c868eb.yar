rule MacOS_Trojan_Thiefquest_9130c0f3
{
	meta:
		author = "Elastic Security"
		id = "9130c0f3-5926-4153-87d8-85a591eed929"
		fingerprint = "38916235c68a329eea6d41dbfba466367ecc9aad2b8ae324da682a9970ec4930"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Thiefquest"
		filetype = "executable"

	strings:
		$a1 = "heck_if_targeted" ascii fullword
		$a2 = "check_command" ascii fullword
		$a3 = "askroot" ascii fullword
		$a4 = "iv_rescue_data" ascii fullword

	condition:
		all of them
}
