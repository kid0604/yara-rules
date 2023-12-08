rule Linux_Hacktool_Earthworm_82d5c4cf
{
	meta:
		author = "Elastic Security"
		id = "82d5c4cf-ab96-4644-b1f3-2e95f1b49e7c"
		fingerprint = "400342ab702de1a7ec4dd7e9b415b8823512f74a9abe578f08f7d79265bef385"
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
		$a = { 89 E5 48 83 EC 20 31 C0 89 C1 48 8D 55 F0 48 89 7D F8 48 8B }

	condition:
		all of them
}
