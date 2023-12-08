rule MacOS_Trojan_Bundlore_650b8ff4
{
	meta:
		author = "Elastic Security"
		id = "650b8ff4-6cc8-4bfc-ba01-ac9c86410ecc"
		fingerprint = "4f4691f6830684a71e7b3ab322bf6ec4638bf0035adf3177dbd0f02e54b3fd80"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Bundlore variant"
		filetype = "executable"

	strings:
		$a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }

	condition:
		all of them
}
