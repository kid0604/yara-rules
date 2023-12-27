import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_Binary_Embedded_MFA_Browser_Extension_IDs_alt_1
{
	meta:
		author = "ditekSHen"
		description = "Detect binaries embedding considerable number of MFA browser extension IDs."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bhghoamapcdpbohphigoooaddinpkbai" ascii wide nocase
		$s2 = "gaedmjdfmmahhbjefcbgaolhhanlaolb" ascii wide nocase
		$s3 = "oeljdldpnmdbchonielidgobddffflal" ascii wide nocase
		$s4 = "ilgcnhelpchnceeipipijaljkblbcobl" ascii wide nocase
		$s5 = "imloifkgjagghnncjkhggdhalmcnfklk" ascii wide nocase
		$s6 = "fdjamakpfbbddfjaooikfcpapjohcfmg" ascii wide nocase
		$s7 = "fooolghllnmhmmndgjiamiiodkpenpbb" ascii wide nocase
		$s8 = "pnlccmojcmeohlpggmfnbbiapkmbliob" ascii wide nocase
		$s9 = "hdokiejnpimakedhajhdlcegeplioahd" ascii wide nocase
		$s10 = "naepdomgkenhinolocfifgehidddafch" ascii wide nocase
		$s11 = "bmikpgodpkclnkgmnpphehdgcimmided" ascii wide nocase
		$s12 = "oboonakemofpalcgghocfoadofidjkkk" ascii wide nocase
		$s13 = "fmhmiaejopepamlcjkncpgpdjichnecm" ascii wide nocase
		$s14 = "nngceckbapebfimnlniiiahkandclblb" ascii wide nocase
		$s15 = "fiedbfgcleddlbcmgdigjgdfcggjcion" ascii wide nocase
		$s16 = "bfogiafebfohielmmehodmfbbebbbpei" ascii wide nocase
		$s17 = "jhfjfclepacoldmjmkmdlmganfaalklb" ascii wide nocase
		$s18 = "chgfefjpcobfbnpmiokfjjaglahmnded" ascii wide nocase
		$s19 = "igkpcodhieompeloncfnbekccinhapdb" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and 5 of them ) or (8 of them )
}
