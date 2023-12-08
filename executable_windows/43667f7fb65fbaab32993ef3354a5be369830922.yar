import "pe"

rule MAL_CRIME_CobaltGang_Malware_Oct19_1
{
	meta:
		description = "Detects CobaltGang malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/vxsh4d0w/status/1187353649015611392"
		date = "2019-10-24"
		hash1 = "72125933265f884ceb8ab64ab303ea76aaeb7877faee8976d398acd0d0b7356b"
		hash2 = "893339624602c7b3a6f481aed9509b53e4e995d6771c72d726ba5a6b319608a7"
		hash3 = "3c34bbf641df25f9accd05b27b9058e25554fdfea0e879f5ca21ffa460ad2b01"
		os = "windows"
		filetype = "executable"

	strings:
		$op_a1 = { 0f 44 c2 eb 0a 31 c0 80 fa 20 0f 94 c0 01 c0 5d }
		$op_b1 = { 89 e5 53 8b 55 08 8b 4d 0c 8a 1c 01 88 1c 02 83 }
		$op_b2 = { 89 e5 53 8b 55 08 8b 45 0c 8a 1c 0a 88 1c 08 83 }

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and (pe.imphash()=="d1e3f8d02cce09520379e5c1e72f862f" or pe.imphash()=="8e26df99c70f79cb8b1ea2ef6f8e52ac" or ($op_a1 and 1 of ($op_b*)))
}
