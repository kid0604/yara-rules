rule Linux_Hacktool_Lightning_3bcac358
{
	meta:
		author = "Elastic Security"
		id = "3bcac358-b4b9-43ae-b173-bebe0c9ff899"
		fingerprint = "7108fab0ed64416cf16134475972f99c24aaaf8a4165b83287f9bdbf5050933b"
		creation_date = "2022-11-08"
		last_modified = "2024-02-13"
		threat_name = "Linux.Hacktool.Lightning"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		reference_sample = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Lightning"
		filetype = "script"

	strings:
		$a1 = "[+] %s:%s %d,ntop:%s,strport:%s" ascii fullword
		$a2 = "%s: reading file \"%s\"" ascii fullword
		$a3 = "%s: kill(%d): %s" ascii fullword
		$a4 = "%s exec \"%s\": %s" ascii fullword

	condition:
		all of them
}
