rule Linux_Generic_Threat_8299c877
{
	meta:
		author = "Elastic Security"
		id = "8299c877-a0c3-4673-96c7-58c80062e316"
		fingerprint = "bae38e2a147dc82ffd66e89214d12c639c690f3d2e701335969f090a21bf0ba7"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "60c486049ec82b4fa2e0a53293ae6476216b76e2c23238ef1c723ac0a2ae070c"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { D0 4D E2 0D 10 A0 E1 07 00 A0 E3 1E 00 00 EB 00 00 50 E3 00 00 9D A5 01 0C A0 B3 0C D0 8D E2 04 E0 9D E4 1E FF 2F E1 04 70 2D E5 CA 70 A0 E3 00 00 00 EF 80 00 BD E8 1E FF 2F E1 04 70 2D E5 C9 }

	condition:
		all of them
}
