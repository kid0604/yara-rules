import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store
{
	meta:
		description = "Detects executables referencing many confidential data stores found in browsers, mail clients, cryptocurreny wallets, etc. Observed in information stealers"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "key3.db" nocase ascii wide
		$s2 = "key4.db" nocase ascii wide
		$s3 = "cert8.db" nocase ascii wide
		$s4 = "logins.json" nocase ascii wide
		$s5 = "account.cfn" nocase ascii wide
		$s6 = "wand.dat" nocase ascii wide
		$s7 = "wallet.dat" nocase ascii wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
