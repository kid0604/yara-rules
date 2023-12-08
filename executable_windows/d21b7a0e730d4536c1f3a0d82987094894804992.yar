import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_Reverse_URL
{
	meta:
		author = "ditekSHen"
		description = "Detects executables (downloaders) containing reversed URLs to raw contents of a paste"
		os = "windows"
		filetype = "executable"

	strings:
		$u1 = "/moc.nibetsap//:sptth" ascii wide nocase
		$u2 = "/ee.etsap//:sptth" ascii wide nocase
		$u3 = "/zyx.edocetsap//:sptth" ascii wide nocase
		$u4 = "/oc.yrtner//:sptth" ascii wide nocase
		$u5 = "/ten.mocern.etsap//:sptth" ascii wide nocase
		$u6 = "/moc.nibetsah//:sptth" ascii wide nocase
		$u7 = "/ofni.nibetavirp//:sptth" ascii wide nocase
		$u8 = "/gro.mocaynep//:sptth" ascii wide nocase
		$u9 = "/moc.clortnoc//:sptth" ascii wide nocase
		$u10 = "/moc.etsap-ynit//:sptth" ascii wide nocase
		$u11 = "/oi.kinket.etsap//:sptth" ascii wide nocase
		$u12 = "/moc.etonvirp//:sptth" ascii wide nocase
		$u13 = "/moc.ppaukoreh.etonhsuh//:sptth" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 1 of ($u*)
}
