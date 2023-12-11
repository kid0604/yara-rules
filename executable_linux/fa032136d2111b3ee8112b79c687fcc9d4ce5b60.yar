rule Linux_Hacktool_Earthworm_e3da43e2
{
	meta:
		author = "Elastic Security"
		id = "e3da43e2-1737-4c51-af6c-7c64d9cbfb07"
		fingerprint = "fdf19096c6afc1c3be75fe4bb2935aca8ac915c97ad0ab3c2b87e803347cc460"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Earthworm"
		reference_sample = "da0cffc4222d11825778fe4fa985fef2945caa0cc3b4de26af0a06509ebafb21"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Earthworm"
		filetype = "executable"

	strings:
		$a = { 8D 20 FF FF FF 4C 89 C1 4C 8B 85 20 FF FF FF 49 D3 E0 4C 21 C7 48 83 }

	condition:
		all of them
}
