rule cred_local
{
	meta:
		author = "x0r"
		description = "Steal credential"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "LsaEnumerateLogonSessions"
		$c2 = "SamIConnect"
		$c3 = "SamIGetPrivateData"
		$c4 = "SamQueryInformationUse"
		$c5 = "CredEnumerateA"
		$c6 = "CredEnumerateW"
		$r1 = "software\\microsoft\\internet account manager" nocase
		$r2 = "software\\microsoft\\identitycrl\\creds" nocase
		$r3 = "Security\\Policy\\Secrets"

	condition:
		any of them
}
