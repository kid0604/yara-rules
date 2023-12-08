rule Linux_Hacktool_Flooder_9417f77b
{
	meta:
		author = "Elastic Security"
		id = "9417f77b-190b-4834-b57a-08a7cbfac884"
		fingerprint = "d321ea7aeb293f8f50236bddeee99802225b70e8695bb3527a89beea51e3ffb3"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "60ff13e27dad5e6eadb04011aa653a15e1a07200b6630fdd0d0d72a9ba797d68"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 0F B7 45 F6 0F B7 C0 48 01 C3 48 89 DA 48 C1 FA 10 0F B7 C3 48 8D }

	condition:
		all of them
}
