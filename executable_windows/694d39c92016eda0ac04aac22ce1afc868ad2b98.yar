import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_AdsBlocker_Browser_Extension_IDs_alt_1
{
	meta:
		author = "ditekSHen"
		description = "Detect executables referencing considerable number of Ads blocking browser extension IDs"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "gighmmpiobklfepjocnamgkkbiglidom" ascii wide nocase
		$s2 = "cfhdojbkjhnklbpkdaibdccddilifddb" ascii wide nocase
		$s3 = "cjpalhdlnbpafiamejdnhcphjbkeiagm" ascii wide nocase
		$s4 = "epcnnfbjfcgphgdmggkamkmgojdagdnn" ascii wide nocase
		$s5 = "kacljcbejojnapnmiifgckbafkojcncf" ascii wide nocase
		$s6 = "gginmiamniniinhbipmknjiefidjlnob" ascii wide nocase
		$s7 = "alplpnakfeabeiebipdmaenpmbgknjce" ascii wide nocase
		$s8 = "ohahllgiabjaoigichmmfljhkcfikeof" ascii wide nocase
		$s9 = "lmiknjkanfacinilblfjegkpajpcpjce" ascii wide nocase
		$s10 = "lalfpjdbhpmnhfofkckdpkljeilmogfl" ascii wide nocase
		$s11 = "ddkjiahejlhfcafbddmgiahcphecmpfh" ascii wide nocase
		$s12 = "bgnkhhnnamicmpeenaelnjfhikgbkllg" ascii wide nocase
		$s13 = "odfafepnkmbhccpbejgmiehpchacaeak" ascii wide nocase
		$s14 = "uBlock0@raymondhill.net.xpi" ascii wide nocase
		$s15 = "uBOLite@raymondhill.net.xpi" ascii wide nocase
		$s16 = "adguardadblocker@adguard.com.xpi" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and 5 of them ) or (7 of them )
}
