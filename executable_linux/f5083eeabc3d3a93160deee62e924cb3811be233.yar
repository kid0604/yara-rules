rule APT_MAL_LNX_Kobalos_SSH_Credential_Stealer
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Leveille"
		date = "2020-11-02"
		reference = "https://www.welivesecurity.com/2021/02/02/kobalos-complex-linux-threat-high-performance-computing-infrastructure/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		os = "linux"
		filetype = "executable"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		uint16(0)==0x457f and any of them
}
