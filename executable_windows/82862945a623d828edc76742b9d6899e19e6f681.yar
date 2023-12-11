import "pe"

rule SUSP_Imphash_PassRevealer_PY_EXE
{
	meta:
		description = "Detects an imphash used by password revealer and hack tools (some false positives with hardware driver installers)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		modified = "2021-11-09"
		score = 40
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
		os = "windows"
		filetype = "executable"

	strings:
		$fp1 = "Assmann Electronic GmbH" ascii wide
		$fp2 = "Oculus VR" ascii wide
		$fp3 = "efm8load" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and pe.imphash()=="ed61beebc8d019dd9bec823e2d694afd" and not 1 of ($fp*)
}
