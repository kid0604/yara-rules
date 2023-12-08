import "pe"

rule INDICATOR_EXE_Packed_TriumphLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects TriumphLoader"
		snort2_sid = "920101"
		snort3_sid = "920099"
		clamav_sig = "INDICATOR.Packed.TriumphLoader"
		os = "windows"
		filetype = "executable"

	strings:
		$id1 = "User-Agent: TriumphLoader" ascii wide
		$id2 = "\\loader\\absent-loader-master\\client\\full\\absentclientfull\\absentclientfull\\absent\\json.hpp" wide
		$id3 = "\\triumphloader\\triumphloaderfiles\\triumph\\json.h" wide
		$s1 = "current == '\\\"'" fullword wide
		$s2 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
		$s3 = "646566676869707172737475767778798081828384858687888990919293949596979899object key" fullword ascii
		$s4 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
		$s5 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide
		$s6 = "p2 <= (std::numeric_limits<std::uint64_t>::max)() / 10" fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($id*) or all of ($s*) or (3 of ($s*) and 1 of ($id*)) or (4 of them and pe.imphash()=="784001f4b755832ae9085d98afc9ce83"))
}
