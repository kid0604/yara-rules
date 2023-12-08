rule VoidCrypt
{
	meta:
		author = "rivitna"
		family = "ransomware.voidcrypt.windows"
		description = "VoidCrypt ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Users\\Legion\\source\\repos\\curl\\" ascii
		$s2 = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNMQWERTYUIOPASDFGHJKLZXCVBNM" ascii
		$s3 = "C:\\ProgramData\\IDk.txt" ascii
		$s4 = "C:\\ProgramData\\pkey.txt" ascii
		$s5 = "C:\\ProgramData\\prvkey" ascii
		$s6 = "fuckyoufuckyoufuckyoufuckyoufuckyou" ascii
		$s7 = "\x00net stop MSSQL$CONTOSO1\x00" ascii
		$s8 = "https://api.my-ip.io/ip" ascii
		$s9 = "\x00threaad\x00"
		$s10 = "\x00  Disksize=\x00"

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((5 of ($s*)))
}
