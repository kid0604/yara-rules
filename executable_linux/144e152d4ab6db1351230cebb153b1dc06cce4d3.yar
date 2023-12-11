rule Linux_Hacktool_Earthworm_4ec2ec63
{
	meta:
		author = "Elastic Security"
		id = "4ec2ec63-6b22-404f-a217-4e7d32bfbe9f"
		fingerprint = "1dfb594e369ca92a9e3f193499708c4992f6497ff1aa74ae0d6c2475a7e87641"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Earthworm"
		reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Earthworm"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 83 EC 20 BA 04 00 00 00 48 8D 45 F0 48 89 7D F8 89 }

	condition:
		all of them
}
