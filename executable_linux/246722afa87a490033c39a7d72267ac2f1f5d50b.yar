rule APT_MAL_LNX_Kobalos
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Leveille"
		date = "2020-11-02"
		reference = "https://www.welivesecurity.com/2021/02/02/kobalos-complex-linux-threat-high-performance-computing-infrastructure/"
		source = "https://github.com/eset/malware-ioc/"
		license = "BSD 2-Clause"
		version = "1"
		os = "linux"
		filetype = "executable"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		uint16(0)==0x457f and any of them
}
