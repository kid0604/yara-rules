rule MacOS_Virus_Maxofferdeal_f4681eba
{
	meta:
		author = "Elastic Security"
		id = "f4681eba-20f5-4e92-9f99-00cd57412c45"
		fingerprint = "b6663c326e9504510b804bd9ff0e8ace5d98826af2bb2fa2429b37171b7f399d"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Virus.Maxofferdeal"
		reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Virus.Maxofferdeal"
		filetype = "executable"

	strings:
		$a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }

	condition:
		all of them
}
