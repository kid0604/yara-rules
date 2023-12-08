import "pe"

rule MacControlCode : MacControl Family
{
	meta:
		description = "MacControl code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-17"
		os = "macos"
		filetype = "executable"

	strings:
		$L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
		$L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
		$L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
		$L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
		$GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }

	condition:
		all of ($L4*) or $GEThgif
}
