import "pe"

rule MiniASP_alt_1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of MiniASP malware associated with the CommentCrew threat (APT1)"
		os = "windows"
		filetype = "executable"

	strings:
		$KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
		$PDB = "MiniAsp.pdb" nocase wide ascii

	condition:
		any of them
}
