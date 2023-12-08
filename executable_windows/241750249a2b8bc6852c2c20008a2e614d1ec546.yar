import "pe"

rule MALWARE_Win_UNK_InfoStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown information stealer"
		snort_sid = "920263"
		hash1 = "b7a2cb34d3bc42d6d4c9d9af7dd406e2a5caef8ea46e5d09773feeb9920a6b21"
		hash2 = "dd95377842932d77e225b126749e1e6e8ecd6f5c6540d084a551a80a54d02d7d"
		hash3 = "12f790d9a0775b5e62effc6ea9e55bbef345fffbfb2f671f85098c4f7661dd0f"
		hash4 = "0a4cea763dffde451c75a434143fc5d014c32c6d1f8f34920ea5f2854e62118f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\%s\\%s-Qt" fullword wide
		$s2 = "%s\\%s.json" fullword wide
		$s3 = "*.mmd*" fullword wide
		$s4 = "%s\\%s.vdf" fullword wide
		$s5 = "%-50s %s" fullword wide
		$s6 = "dISCORD|lOCAL" fullword ascii nocase
		$s7 = "sTORAGE|LEVELDB" fullword ascii nocase
		$s8 = ".coin" fullword ascii
		$s9 = ".emc" fullword ascii
		$s10 = ".lib" fullword ascii
		$s11 = ".bazar" fullword ascii
		$s12 = "id=%d" fullword ascii
		$s13 = "2:?/v /v /v /^Y" fullword ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
