import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_PasswordManagers
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing many Password Manager software clients. Observed in infostealers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "1Password\\" ascii wide nocase
		$s2 = "Dashlane\\" ascii wide nocase
		$s3 = "nordpass*.sqlite" ascii wide nocase
		$s4 = "RoboForm\\" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
