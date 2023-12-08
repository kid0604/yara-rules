import "pe"

rule HKTL_mimikatz_icon
{
	meta:
		description = "Detects mimikatz icon in PE file"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
		author = "Arnim Rupp"
		reference = "https://blog.gentilkiwi.com/mimikatz"
		date = "2023-02-18"
		score = 60
		hash1 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"
		hash2 = "1c3f584164ef595a37837701739a11e17e46f9982fdcee020cf5e23bad1a0925"
		hash3 = "c6bb98b24206228a54493274ff9757ce7e0cbb4ab2968af978811cc4a98fde85"
		hash4 = "721d3476cdc655305902d682651fffbe72e54a97cd7e91f44d1a47606bae47ab"
		hash5 = "c0f3523151fa307248b2c64bdaac5f167b19be6fccff9eba92ac363f6d5d2595"
		os = "windows"
		filetype = "executable"

	strings:
		$ico = {79 e1 d7 ff 7e e5 db ff 7f e8 dc ff 85 eb dd ff ba ff f1 ff 66 a0 b6 ff 01 38 61 ff 22 50 75 c3}

	condition:
		uint16(0)==0x5A4D and $ico and filesize <10MB
}
