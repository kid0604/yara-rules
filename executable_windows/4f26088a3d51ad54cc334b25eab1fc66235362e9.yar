import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_References_GitConfData
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing potentially confidential GIT artifacts. Observed in infostealer"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GithubDesktop\\Local Storage" ascii wide nocase
		$s2 = "GitHub Desktop\\Local Storage" ascii wide nocase
		$s3 = ".git-credentials" ascii wide
		$s4 = ".config\\git\\credentials" ascii wide
		$s5 = ".gitconfig" ascii wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
