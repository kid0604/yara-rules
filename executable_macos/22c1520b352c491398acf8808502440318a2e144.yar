rule MacOS_Trojan_Genieo_9e178c0b
{
	meta:
		author = "Elastic Security"
		id = "9e178c0b-02ca-499b-93d1-2b6951d41435"
		fingerprint = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Genieo"
		reference_sample = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Genieo variant with fingerprint 9e178c0b"
		filetype = "executable"

	strings:
		$a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }

	condition:
		all of them
}
