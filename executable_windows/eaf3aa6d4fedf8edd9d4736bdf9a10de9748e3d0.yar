import "hash"
import "pe"

rule APT_MAL_REvil_Kaseya_Jul21_1
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 9"
		detail = "Detects malware used in the Kaseya supply chain attack"
		hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
		hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
		hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
		hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mpsvc.dll" wide fullword
		$s2 = ":0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:H<L<P<\\<`<" ascii fullword
		$op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
		$op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
		$op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
		$op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
		$op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (pe.imphash()=="c36dcd2277c4a707a1a645d0f727542a" or 2 of them )
}
