rule Windows_Generic_Threat_ebf62328
{
	meta:
		author = "Elastic Security"
		id = "ebf62328-f069-43f2-b943-6ddf64f04fb2"
		fingerprint = "44cce86a986cbb051f1b94c2d5b54830cbe7de1f3387e207bd6b267a5166bbe7"
		creation_date = "2024-02-14"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "dfce19aa2e1a3e983c3bfb2e4bbd7617b96d57602d7a6da6fee7b282e354c9e1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 74 52 75 50 5B 5D 5F 5E 41 5C 41 5D 41 5E }
		$a2 = { 5F 5E 41 5C 41 5E 41 5F 74 7A 75 78 }
		$a3 = { 44 64 71 52 71 77 7C 61 69 41 66 6E 68 73 6F 72 48 60 6C 65 49 46 }

	condition:
		all of them
}
