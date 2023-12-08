rule Asmodeus_v0_1_pl
{
	meta:
		description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0978b672db0657103c79505df69cb4bb"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "[url=http://www.governmentsecurity.org"
		$s1 = "perl asmodeus.pl client 6666 127.0.0.1"
		$s2 = "print \"Asmodeus Perl Remote Shell"
		$s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword

	condition:
		2 of them
}
