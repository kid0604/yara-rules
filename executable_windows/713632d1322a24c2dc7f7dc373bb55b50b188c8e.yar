import "pe"

rule CDSSSv10Beta1CyberDoomTeamX
{
	meta:
		author = "malware-lu"
		description = "Detects CDSSSv10Beta1CyberDoomTeamX malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }

	condition:
		$a0 at pe.entry_point
}
