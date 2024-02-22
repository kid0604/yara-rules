import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_Crypto_Wallet_Regex
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing cryptocurrency wallet regular expressions"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii wide nocase
		$s2 = "(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)" ascii wide nocase
		$s3 = "(?:^0x[a-fA-F0-9]{40}$)" ascii wide nocase
		$s4 = "(?:^G[0-9a-zA-Z]{55}$)" ascii wide nocase
		$s5 = "^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)" ascii wide nocase
		$s6 = "(^[1-9A-HJ-NP-Za-km-z]{44}$)" ascii wide nocase
		$s7 = "T[A-Za-z1-9]{33}" ascii wide nocase
		$s8 = "(?:^r[0-9a-zA-Z]{24,34}$)" ascii wide nocase
		$s9 = "^((bitcoincash:)?(q|p)[a-z0-9]{41})" ascii wide nocase
		$s10 = "(?:^X[1-9A-HJ-NP-Za-km-z]{33}$)" ascii wide nocase
		$s11 = "(?:^A[0-9a-zA-Z]{33}$)" ascii wide nocase
		$s12 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" ascii wide nocase
		$s13 = "(^0x[A-Za-z0-9]{40,40}?[\\d\\- ])|(^0x[A-Za-z0-9]{40,40})$" ascii wide nocase
		$s14 = "(^D[A-Za-z0-9]{32,35}?[\\d\\- ])|(^D[A-Za-z0-9]{32,35})$" ascii wide nocase
		$s15 = "^([13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})$" ascii wide nocase
		$s16 = "(^X[A-Za-z0-9]{32,34}?[\\d\\- ])|(^X[A-Za-z0-9]{32,34})|(^7[A-Za-z0-9]{32,34})$" ascii wide nocase
		$s17 = "(^t[A-Za-z0-9]{32,36})$" ascii wide nocase
		$s18 = "(^(GD|GC)[A-Z0-9]{54,56})$" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and 3 of them ) or (5 of them )
}
