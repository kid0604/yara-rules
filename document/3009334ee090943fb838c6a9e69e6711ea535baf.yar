rule PoseidonGroup_MalDoc_2
{
	meta:
		description = "Detects Poseidon Group - Malicious Word Document"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
		date = "2016-02-09"
		score = 70
		hash1 = "3e4cacab0ff950da1c6a1c640fe6cf5555b99e36d4e1cf5c45f04a2048f7620c"
		hash2 = "1f77475d7740eb0c5802746d63e93218f16a7a19f616e8fddcbff07983b851af"
		hash3 = "f028ee20363d3a17d30175508bbc4738dd8e245a94bfb200219a40464dd09b3a"
		hash4 = "ec309300c950936a1b9f900aa30630b33723c42240ca4db978f2ca5e0f97afed"
		hash5 = "27449198542fed64c23f583617908c8648fa4b4633bacd224f97e7f5d8b18778"
		hash6 = "1e62629dae05bf7ee3fe1346faa60e6791c61f92dd921daa5ce2bdce2e9d4216"
		os = "windows"
		filetype = "document"

	strings:
		$s0 = "{\\*\\generator Msftedit 5.41." ascii
		$s1 = "Attachment 1: Complete Professional Background" ascii
		$s2 = "E-mail:  \\cf1\\ul\\f1"
		$s3 = "Education:\\par" ascii
		$s5 = "@gmail.com" ascii

	condition:
		uint32(0)==0x74725c7b and filesize <500KB and 3 of them
}
