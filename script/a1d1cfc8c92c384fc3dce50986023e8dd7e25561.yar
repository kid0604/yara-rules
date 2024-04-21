rule BKDR_XZUtil_Script_CVE_2024_3094_Mar24_1
{
	meta:
		description = "Detects make file and script contents used by the backdoored XZ library (xzutil) CVE-2024-3094."
		author = "Florian Roth"
		reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
		date = "2024-03-30"
		score = 80
		hash = "d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "/bad-3-corrupt_lzma2.xz | tr " ascii
		$x2 = "/tests/files/good-large_compressed.lzma|eval $i|tail -c +31265|" ascii
		$x3 = "eval $zrKcKQ" ascii

	condition:
		1 of them
}
