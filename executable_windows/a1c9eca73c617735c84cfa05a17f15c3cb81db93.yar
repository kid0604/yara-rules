import "pe"

rule NakedPacker10byBigBoote
{
	meta:
		author = "malware-lu"
		description = "Detects the NakedPacker10byBigBoote malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 FC 0F B6 05 34 [3] 85 C0 75 31 B8 50 [3] 2B 05 04 [3] A3 30 [3] A1 00 [3] 03 05 30 [3] A3 38 [3] E8 9A 00 00 00 A3 50 [3] C6 05 34 [3] 01 83 3D 50 [3] 00 75 07 61 FF 25 38 [3] 61 FF 74 24 04 6A 00 FF 15 44 [3] 50 FF 15 40 [3] C3 FF 74 24 04 6A 00 FF 15 44 [3] 50 FF 15 48 [3] C3 8B 4C 24 04 56 8B 74 24 10 57 85 F6 8B F9 74 0D 8B 54 24 10 8A 02 88 01 }

	condition:
		$a0
}
