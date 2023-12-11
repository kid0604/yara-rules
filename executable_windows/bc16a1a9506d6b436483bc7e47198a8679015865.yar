import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_NKN_BCP2P
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing NKN Blockchain P2P network"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "/nknorg/nkn-sdk-go." ascii
		$x2 = "://seed.nkn.org" ascii
		$x3 = "/nknorg/nkn/" ascii
		$s1 = ").NewNanoPayClaimer" ascii
		$s2 = ").IncrementAmount" ascii
		$s3 = ").BalanceByAddress" ascii
		$s4 = ").TransferName" ascii
		$s5 = ".GetWsAddr" ascii
		$s6 = ".GetNodeStateContext" ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($s*))
}
