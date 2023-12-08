rule PoseidonGroup_MalDoc_1
{
	meta:
		description = "Detects Poseidon Group - Malicious Word Document"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
		date = "2016-02-09"
		score = 80
		hash = "0983526d7f0640e5765ded6be6c9e64869172a02c20023f8a006396ff358999b"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "c:\\cmd32dll.exe" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and all of them
}
