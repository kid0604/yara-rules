import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_ASEP_REG_Reverse
{
	meta:
		author = "ditekSHen"
		description = "Detects file containing reversed ASEP Autorun registry keys"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
		$s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
		$s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
		$s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
		$s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
		$s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
		$s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
		$s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase

	condition:
		1 of them and filesize <2000KB
}
